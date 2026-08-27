//! One-off generator for independent-review cryptographic test vectors.
//! Digests always come from `AntechEngine::derive`. Intermediates use the same
//! core primitives as the engine loop.

use antech_kdf::{
    hash_with_config_and_salt, hash_with_inputs_and_salt, AntechConfig as PubConfig, DeriveInputs,
    GraphKind as PubGraph, SecretBytes,
};
use antech_kdf_core::graph::{self, MAX_PARENTS};
use antech_kdf_core::memory::FrontierRing;
use antech_kdf_core::state::{
    bind_seed, finalize, mix_parent_views, phantom_block, seed_to_state, state_to_block_fast,
    xor_state_into_block_fast,
};
use antech_kdf_core::AntechEngine;
use antech_kdf_types::{AntechConfig, GraphKind};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

fn hex_decode(s: &str) -> Vec<u8> {
    if s.is_empty() {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn refresh_sdk_vectors() {
    let path = PathBuf::from("sdk/conformance/vectors.json");
    if !path.exists() {
        eprintln!("skip sdk vectors (not found)");
        return;
    }
    let mut v: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    for case in v["cases"].as_array_mut().unwrap() {
        let password = hex_decode(case["password_hex"].as_str().unwrap_or(""));
        let salt = hex_decode(case["salt_hex"].as_str().unwrap());
        let cfgj = &case["config"];
        let graph = PubGraph::from_tag(cfgj["graph"].as_u64().unwrap() as u32).unwrap();
        let cfg = PubConfig::builder()
            .memory_kib(cfgj["memory_kib"].as_u64().unwrap() as usize)
            .salt_length(cfgj["salt_length"].as_u64().unwrap() as usize)
            .block_size(cfgj["block_size"].as_u64().unwrap() as usize)
            .fan_in(cfgj["fan_in"].as_u64().unwrap() as u32)
            .graph(graph)
            .output_length(cfgj["output_length"].as_u64().unwrap() as usize)
            .build()
            .unwrap();
        let encoded = if case.get("secret_hex").is_some() || case.get("associated_data_hex").is_some()
        {
            let mut inputs = DeriveInputs::default();
            if let Some(s) = case.get("secret_hex") {
                inputs.secret = Some(SecretBytes::new(hex_decode(s.as_str().unwrap())).unwrap());
            }
            if let Some(a) = case.get("associated_data_hex") {
                inputs.associated_data = Some(hex_decode(a.as_str().unwrap()));
            }
            hash_with_inputs_and_salt(&password, &salt, &cfg, &inputs).unwrap()
        } else {
            hash_with_config_and_salt(&password, &salt, &cfg).unwrap()
        };
        let digest = encoded.rsplit('$').next().unwrap();
        case["digest_hex"] = json!(digest);
    }
    fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    eprintln!("Updated {}", path.display());
}

fn gather_mix(
    state: &mut [u64; 4],
    buffer: &[u8],
    ring: &FrontierRing,
    block_size: usize,
    parents: &[usize],
) {
    if parents.is_empty() {
        return;
    }
    let mut views: [&[u8]; MAX_PARENTS] = [&[]; MAX_PARENTS];
    let mut n_views = 0usize;
    for &p in parents {
        views[n_views] = match ring.get(p) {
            Some(v) => v,
            None => &buffer[p * block_size..(p + 1) * block_size],
        };
        n_views += 1;
    }
    mix_parent_views(state, &views[..n_views]);
}

fn state_hex(state: &[u64; 4]) -> [String; 4] {
    [
        format!("{:016x}", state[0]),
        format!("{:016x}", state[1]),
        format!("{:016x}", state[2]),
        format!("{:016x}", state[3]),
    ]
}

fn config_json(cfg: &AntechConfig) -> Value {
    json!({
        "algorithm": cfg.algorithm.as_str(),
        "memory_kib": cfg.memory.as_kib(),
        "salt_length": cfg.salt_length.as_bytes(),
        "block_size": cfg.block_size.as_bytes(),
        "fan_in": cfg.fan_in.get(),
        "graph": cfg.graph.as_str(),
        "output_length": cfg.output_length.as_bytes(),
        "num_blocks": cfg.num_blocks(),
        "critical_period": cfg.critical_period(),
        "tile_len": cfg.tile_len(),
        "construction_version": antech_kdf_core::CONSTRUCTION_VERSION,
        "mix_rounds": antech_kdf_core::MIX_ROUNDS,
        "frontier_width": antech_kdf_core::FRONTIER_WIDTH,
    })
}

fn derive_digest(password: &[u8], salt: &[u8], cfg: &AntechConfig) -> Vec<u8> {
    AntechEngine::new()
        .derive(password, salt, cfg)
        .expect("AntechEngine::derive must succeed for test vectors")
}

/// Reimplementation of the engine loop that records selected node intermediates.
/// Final digest is always taken from `AntechEngine::derive` (verified equal here).
fn derive_with_intermediates(
    password: &[u8],
    salt: &[u8],
    cfg: &AntechConfig,
    capture_nodes: &[usize],
) -> Value {
    const MAX_BLOCK: usize = 64;
    let block_size = cfg.block_size.as_bytes();
    assert!(block_size <= MAX_BLOCK);

    let num_blocks = cfg.num_blocks();
    let period = cfg.critical_period();
    let tile_len = cfg.tile_len();
    let seed = bind_seed(password, salt, cfg);
    let mut buffer = vec![0u8; cfg.memory.as_bytes()];
    let mut state = seed_to_state(&seed);
    let initial_state = state;
    let mut ring = FrontierRing::new(block_size);

    let mut phantoms = [[0u8; MAX_BLOCK]; MAX_PARENTS];
    let fan = (cfg.fan_in.get() as usize).min(MAX_PARENTS);
    for slot in 0..fan {
        phantom_block(
            &seed,
            slot as u32,
            block_size,
            &mut phantoms[slot][..block_size],
        );
    }

    let mut node_records: Vec<Value> = Vec::new();

    for i in 0..num_blocks {
        let mut parents_list: Vec<usize> = Vec::new();
        let mut scatter_dest = None;
        let mut scatter_dest2 = None;

        if i == 0 {
            let mut views: [&[u8]; MAX_PARENTS] = [&[]; MAX_PARENTS];
            for slot in 0..fan {
                views[slot] = &phantoms[slot][..block_size];
            }
            mix_parent_views(&mut state, &views[..fan]);
        } else {
            let local = graph::combined_local_parents(&state, i);
            parents_list.extend_from_slice(local.as_slice());
            gather_mix(&mut state, &buffer, &ring, block_size, local.as_slice());

            let remote =
                graph::combined_remote_parents(&state, i, cfg.fan_in.get(), period, tile_len);
            parents_list.extend_from_slice(remote.as_slice());
            gather_mix(&mut state, &buffer, &ring, block_size, remote.as_slice());

            let (s1, s2) = graph::scatter_dests_from_state(&state, i);
            scatter_dest = s1;
            scatter_dest2 = s2;
        }

        {
            let out = &mut buffer[i * block_size..(i + 1) * block_size];
            state_to_block_fast(&state, out);
            ring.push(i, out);
        }

        // Capture pristine block bytes immediately after write (before this node's scatters).
        let capture = capture_nodes.contains(&i);
        let pristine_block: Option<Vec<u8>> = if capture {
            Some(buffer[i * block_size..(i + 1) * block_size].to_vec())
        } else {
            None
        };

        let applied_scatter = scatter_dest.filter(|&dest| dest < num_blocks && dest != i);
        let applied_scatter2 = scatter_dest2.filter(|&dest| dest < num_blocks && dest != i);

        if let Some(dest) = applied_scatter {
            xor_state_into_block_fast(
                &state,
                &mut buffer[dest * block_size..(dest + 1) * block_size],
            );
        }
        if let Some(dest) = applied_scatter2 {
            xor_state_into_block_fast(
                &state,
                &mut buffer[dest * block_size..(dest + 1) * block_size],
            );
        }

        if capture {
            node_records.push(json!({
                "i": i,
                "parents": parents_list,
                "scatter_dest": scatter_dest,
                "scatter_dest2": scatter_dest2,
                "scatter_dest_applied": applied_scatter,
                "scatter_dest2_applied": applied_scatter2,
                "state_after_mix": state_hex(&state),
                "block_after_write_hex": hex_encode(pristine_block.as_ref().unwrap()),
                "note": "v5 two-phase CombinedFrontier: local mix then remote mix; block_after_write_hex is block i immediately after state_to_block, before this node's scatters"
            }));
        }
    }

    let last = &buffer[(num_blocks - 1) * block_size..num_blocks * block_size];
    let mut loop_digest = finalize(&seed, &state, last, cfg.graph);
    let out_len = cfg.output_length.as_bytes();
    if loop_digest.len() > out_len {
        loop_digest.truncate(out_len);
    } else if loop_digest.len() < out_len {
        loop_digest.resize(out_len, 0);
    }
    let engine_digest = derive_digest(password, salt, cfg);
    assert_eq!(
        loop_digest, engine_digest,
        "intermediate loop digest must match AntechEngine::derive"
    );

    json!({
        "password_utf8": String::from_utf8_lossy(password).to_string(),
        "password_hex": hex_encode(password),
        "salt_hex": hex_encode(salt),
        "config": config_json(cfg),
        "seed_hex": hex_encode(&seed),
        "initial_state": state_hex(&initial_state),
        "nodes": node_records,
        "digest_hex": hex_encode(&engine_digest),
        "digest_source": "AntechEngine::derive"
    })
}

fn vector_digest_only(
    id: &str,
    password: &[u8],
    salt: &[u8],
    cfg: &AntechConfig,
    notes: &str,
) -> Value {
    assert_eq!(
        salt.len(),
        cfg.salt_length.as_bytes(),
        "salt length must match config.salt_length for vector {id}"
    );
    let digest = derive_digest(password, salt, cfg);
    json!({
        "id": id,
        "notes": notes,
        "password_utf8": String::from_utf8_lossy(password).to_string(),
        "password_hex": hex_encode(password),
        "salt_hex": hex_encode(salt),
        "config": config_json(cfg),
        "digest_hex": hex_encode(&digest),
        "digest_source": "AntechEngine::derive"
    })
}

fn main() {
    let engine_note =
        "All digests produced by antech_kdf_core::AntechEngine::derive. Intermediates use the same public core primitives as the production engine loop.";

    // --- 1. Canonical default: 16 MiB CombinedFrontier ---
    let default_cfg = AntechConfig::default();
    assert_eq!(default_cfg.memory.as_kib(), 16 * 1024);
    assert_eq!(default_cfg.graph, GraphKind::CombinedFrontier);

    let default_pairs: &[(&str, &[u8], &[u8], &str)] = &[
        (
            "default-16mib-pwd1",
            b"password",
            b"salt_16_bytes_!!",
            "canonical default config; ASCII password",
        ),
        (
            "default-16mib-pwd2",
            b"correct horse battery staple",
            b"0123456789abcdef",
            "canonical default config; passphrase",
        ),
        (
            "default-16mib-pwd3",
            b"AntechReview#2026",
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            "canonical default config; binary salt",
        ),
    ];

    eprintln!(
        "Generating {} default (16 MiB) vectors...",
        default_pairs.len()
    );
    let mut default_vectors = Vec::new();
    for (id, pwd, salt, notes) in default_pairs {
        eprintln!("  deriving {id}...");
        default_vectors.push(vector_digest_only(id, pwd, salt, &default_cfg, notes));
    }

    // --- 2. 1 MiB with intermediates ---
    let small_cfg = AntechConfig::builder()
        .memory_kib(1024)
        .graph(GraphKind::CombinedFrontier)
        .build()
        .expect("1 MiB CombinedFrontier config");

    let capture: Vec<usize> = {
        let n = small_cfg.num_blocks();
        [0usize, 1, 2, 3, 10, 100, 1000]
            .into_iter()
            .filter(|&i| i < n)
            .collect()
    };

    eprintln!(
        "Generating 1 MiB intermediate vectors (num_blocks={}, capture={:?})...",
        small_cfg.num_blocks(),
        capture
    );

    let inter_a = {
        let pwd = b"vector-inter-a";
        let salt = b"salt_16_bytes_!!";
        let mut v = derive_with_intermediates(pwd, salt, &small_cfg, &capture);
        if let Value::Object(ref mut m) = v {
            m.insert("id".into(), json!("small-1mib-intermediates-a"));
            m.insert(
                "notes".into(),
                json!("1 MiB CombinedFrontier with node intermediates; digest from AntechEngine::derive"),
            );
        }
        v
    };

    let inter_b = {
        let pwd = b"vector-inter-b\x00tail";
        let salt = b"abcdef0123456789";
        let mut v = derive_with_intermediates(pwd, salt, &small_cfg, &capture);
        if let Value::Object(ref mut m) = v {
            m.insert("id".into(), json!("small-1mib-intermediates-b"));
            m.insert(
                "notes".into(),
                json!("1 MiB CombinedFrontier; password contains embedded NUL; digest from AntechEngine::derive"),
            );
        }
        v
    };

    // --- 3. Boundary configs at 1 MiB ---
    eprintln!("Generating boundary (1 MiB) vectors...");
    let mut boundary = Vec::new();

    let fan2 = AntechConfig::builder()
        .memory_kib(1024)
        .graph(GraphKind::CombinedFrontier)
        .fan_in(2)
        .salt_length(8)
        .build()
        .unwrap();
    boundary.push(vector_digest_only(
        "boundary-1mib-fan2-salt8",
        b"boundary",
        b"saltsalt",
        &fan2,
        "fan_in=2, salt_length=8",
    ));

    let fan4 = AntechConfig::builder()
        .memory_kib(1024)
        .graph(GraphKind::CombinedFrontier)
        .fan_in(4)
        .salt_length(32)
        .build()
        .unwrap();
    boundary.push(vector_digest_only(
        "boundary-1mib-fan4-salt32",
        b"boundary",
        b"0123456789abcdef0123456789abcdef",
        &fan4,
        "fan_in=4, salt_length=32",
    ));

    let empty_pwd_cfg = AntechConfig::builder()
        .memory_kib(1024)
        .graph(GraphKind::CombinedFrontier)
        .build()
        .unwrap();
    boundary.push(vector_digest_only(
        "boundary-1mib-empty-password",
        b"",
        b"salt_16_bytes_!!",
        &empty_pwd_cfg,
        "empty password",
    ));

    let null_pwd = b"pre\x00mid\x00post";
    boundary.push(vector_digest_only(
        "boundary-1mib-null-bytes-password",
        null_pwd,
        b"salt_16_bytes_!!",
        &empty_pwd_cfg,
        "binary password with embedded NUL bytes",
    ));

    let long_pwd: Vec<u8> = (0u8..200).map(|i| b'A' + (i % 26)).collect();
    boundary.push(vector_digest_only(
        "boundary-1mib-long-password",
        &long_pwd,
        b"salt_16_bytes_!!",
        &empty_pwd_cfg,
        "long password (200 bytes cycling A-Z)",
    ));

    // Also fan_in=2 / salt 32 and fan_in=4 / salt 8 for fuller salt-length coverage
    let fan2_s32 = AntechConfig::builder()
        .memory_kib(1024)
        .graph(GraphKind::CombinedFrontier)
        .fan_in(2)
        .salt_length(32)
        .build()
        .unwrap();
    boundary.push(vector_digest_only(
        "boundary-1mib-fan2-salt32",
        b"boundary",
        b"fedcba9876543210fedcba9876543210",
        &fan2_s32,
        "fan_in=2, salt_length=32",
    ));

    let fan4_s8 = AntechConfig::builder()
        .memory_kib(1024)
        .graph(GraphKind::CombinedFrontier)
        .fan_in(4)
        .salt_length(8)
        .build()
        .unwrap();
    boundary.push(vector_digest_only(
        "boundary-1mib-fan4-salt8",
        b"boundary",
        b"abcdefgh",
        &fan4_s8,
        "fan_in=4, salt_length=8",
    ));

    let doc = json!({
        "schema_version": 1,
        "generator": "antech-kdf-research/examples/gen_security_review_vectors.rs",
        "construction": "antech-compute-memory-v5",
        "construction_version": antech_kdf_core::CONSTRUCTION_VERSION,
        "notes": engine_note,
        "canonical_default_16mib": default_vectors,
        "small_1mib_with_intermediates": [inter_a, inter_b],
        "boundary_1mib": boundary,
    });

    // Crate lives at research/code/antech-kdf-research → security-review is ../../security-review
    let out =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../security-review/test-vectors.json");

    let workspace_out = PathBuf::from("research/security-review/test-vectors.json");
    if let Some(parent) = workspace_out.parent() {
        fs::create_dir_all(parent).ok();
    }

    let pretty = serde_json::to_string_pretty(&doc).expect("serialize JSON");
    let write_path = if PathBuf::from("research/security-review").exists() {
        PathBuf::from("research/security-review/test-vectors.json")
    } else {
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).ok();
        }
        out
    };
    fs::write(&write_path, &pretty).expect("write test-vectors.json");
    eprintln!("Wrote {}", write_path.display());
    refresh_sdk_vectors();
}
