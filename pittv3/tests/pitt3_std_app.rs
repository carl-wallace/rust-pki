#![cfg(not(feature = "std"))]

use assert_cmd::prelude::*;
use std::process::Command;

#[cfg(feature = "std_app")]
use predicates::prelude::*;

#[cfg(all(feature = "std_app", not(feature = "revocation")))]
#[test]
fn generate_then_validate_one_std_app() -> Result<(), Box<dyn std::error::Error>> {
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-e").arg("tests/examples/amazon.der");
        cmd.assert()
            .stdout(predicate::str::contains("Valid paths found: 1"));
    }
    Ok(())
}
#[cfg(all(feature = "std_app", feature = "revocation"))]
#[test]
fn generate_then_validate_one_std_app() -> Result<(), Box<dyn std::error::Error>> {
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-e").arg("tests/examples/amazon.der");
        cmd.assert()
            .stdout(predicate::str::contains("Paths found: 1"));
    }
    Ok(())
}

#[cfg(not(feature = "std_app"))]
#[test]
fn generate_then_validate_one_no_std() -> Result<(), Box<dyn std::error::Error>> {
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.assert();
    }
    Ok(())
}
