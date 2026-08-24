//! Concurrency resource controller benchmark exporter.

use crate::resource_controller::run_concurrency_benchmark;
use std::path::Path;

pub fn run_concurrency_benchmarks(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let conc_recs = run_concurrency_benchmark();
    let mut wtr_conc = csv::Writer::from_path(target_dir.join("concurrency-control.csv"))?;
    for conc in &conc_recs {
        wtr_conc.serialize(conc)?;
    }
    wtr_conc.flush()?;
    Ok(())
}
