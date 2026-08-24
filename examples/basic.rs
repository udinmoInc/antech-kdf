use antech_kdf::hash;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = "my_secure_password";
    let stored_hash = hash(password)?;
    println!("Generated Antech KDF hash: {}", stored_hash);
    Ok(())
}
