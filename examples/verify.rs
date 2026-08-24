use antech_kdf::{hash, verify};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = "my_secure_password";
    let stored_hash = hash(password)?;

    let valid = verify("my_secure_password", &stored_hash)?;
    println!("Correct password verification: {}", valid);

    let invalid = verify("wrong_password", &stored_hash)?;
    println!("Wrong password verification: {}", invalid);

    Ok(())
}
