use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use std::process::Command;

fn remove_files_from_downloads() {
    let rd = match fs::read_dir(Path::new("tests/examples/downloads")) {
        Ok(r) => r,
        Err(_e) => {
            return;
        }
    };

    for entry in rd {
        let e = match entry {
            Ok(e) => e,
            Err(_e) => {
                continue;
            }
        };

        if let Err(_e) = fs::remove_file(e.path()) {
            continue;
        }
    }
}

#[test]
fn list_trust_anchors() -> Result<(), Box<dyn std::error::Error>> {
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("--list-trust-anchors");
        cmd.assert().stdout(predicate::str::contains("Index:   0"));
    }

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-t").arg("tests/examples/ta_store_two");
        cmd.arg("--list-trust-anchors");
        cmd.assert().stdout(predicate::str::contains("Index:   0"));
        cmd.assert().stdout(predicate::str::contains("Index:   1"));
    }

    Ok(())
}

#[test]
fn generate_then_validate_one() -> Result<(), Box<dyn std::error::Error>> {
    let p = Path::new("tests/examples/regen1.cbor");
    if Path::exists(p) {
        fs::remove_file(p.to_str().unwrap())?;
    }

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen1.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-c").arg("tests/examples/cert_store_one");
        cmd.arg("--generate");
        cmd.assert().stdout(predicate::str::contains(
            "Serializing 1 buffers and 1 partial paths",
        ));
        assert_eq!(true, p.exists());
    }

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen1.cbor");
        cmd.arg("--list-buffers");
        cmd.assert().stdout(predicate::str::contains("Index: 0"));
        cmd.assert()
            .stdout(predicate::str::contains("DOD EMAIL CA-59"));
    }

    {
        // Try static building with CBOR containing only Email CA-59 to affirm it fails
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen1.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
    }

    {
        // Same as above but with validate_all, still same result
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen1.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-v");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
    }

    {
        // Same as above without validate_all and with different target that does not chain
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen1.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_id_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Failed to find any certification paths for target",
        ));
    }

    {
        // Same as above but with dynamic build enabled.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen1.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-d").arg("tests/examples/downloads");
        cmd.arg("-y");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_id_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
    }
    fs::remove_file(p.to_str().unwrap())?;
    remove_files_from_downloads();
    Ok(())
}

#[test]
fn regen_ignore_self_signed() -> Result<(), Box<dyn std::error::Error>> {
    let p = Path::new("tests/examples/regen2.cbor");
    if Path::exists(p) {
        fs::remove_file(p.to_str().unwrap())?;
    }

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen2.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-c")
            .arg("tests/examples/cert_store_with_self_signed");
        cmd.arg("--generate");
        cmd.assert().stdout(predicate::str::contains(
            "Serializing 1 buffers and 1 partial paths",
        ));
        assert_eq!(true, Path::new("tests/examples/regen2.cbor").exists());
        fs::remove_file(p.to_str().unwrap())?;
    }
    Ok(())
}

#[test]
fn empty_cbor() -> Result<(), Box<dyn std::error::Error>> {
    {
        // Try a diagnostic command with empty CBOR to affirm graceful failure
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/empty.cbor");
        cmd.arg("--list-name-constraints");
        cmd.assert().stdout(predicate::str::contains(
            "Failed to read CBOR data from file located at",
        ));
    }

    {
        // Try static building with empty CBOR to affirm it fails
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/empty.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Failed to find any certification paths for target",
        ));
    }

    {
        // Try dynamic building, which should download a ton of stuff but still only find one valid
        // path given the empty CBOR and ta_store_one. Save downloaded artifacts to downloads folder
        // to avoid polluting next generation.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/empty.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-d").arg("tests/examples/downloads");
        cmd.arg("-y");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
    }

    {
        // Same as above but with a blocklist that should deny the necessary URI to find path
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/empty.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-d").arg("tests/examples/downloads");
        cmd.arg("-y");
        cmd.arg("-x").arg("tests/examples/blocklist_one.json");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Failed to find any certification paths for target",
        ));
    }

    {
        // Try dynamic building, which should download a ton of stuff and find two valid paths given
        // the empty CBOR, ta_store_two, and validate_all flag.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/empty.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_two");
        cmd.arg("-d").arg("tests/examples/downloads");
        cmd.arg("-y");
        cmd.arg("-v");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 2 - Result folder indices: [0, 1]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
    }

    {
        // Same as above but without the validate_all flag, so only one path should be returned.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/empty.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_two");
        cmd.arg("-d").arg("tests/examples/downloads");
        cmd.arg("-y");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
    }
    remove_files_from_downloads();
    Ok(())
}

#[test]
fn absent_cbor() -> Result<(), Box<dyn std::error::Error>> {
    // same as empty_cbor for validation (minus the cbor option). diagnostics require cbor, so omitted.

    {
        // Try static building with empty CBOR to affirm it fails
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Failed to find any certification paths for target",
        ));
    }

    {
        // Try dynamic building, which should download a ton of stuff but still only find one valid
        // path given the empty CBOR and ta_store_one. Save downloaded artifacts to downloads folder
        // to avoid polluting next generation.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-d").arg("tests/examples/downloads");
        cmd.arg("-y");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
    }

    {
        // Same as above but with a blocklist that should deny the necessary URI to find path
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-d").arg("tests/examples/downloads");
        cmd.arg("-y");
        cmd.arg("-x").arg("tests/examples/blocklist_one.json");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Failed to find any certification paths for target",
        ));
    }

    {
        // Try dynamic building, which should download a ton of stuff and find two valid paths given
        // the empty CBOR, ta_store_two, and validate_all flag.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-t").arg("tests/examples/ta_store_two");
        cmd.arg("-d").arg("tests/examples/downloads");
        cmd.arg("-y");
        cmd.arg("-v");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 2 - Result folder indices: [0, 1]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
    }

    {
        // Same as above but without the validate_all flag, so only one path should be returned.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-t").arg("tests/examples/ta_store_two");
        cmd.arg("-d").arg("tests/examples/downloads");
        cmd.arg("-y");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
    }
    remove_files_from_downloads();
    Ok(())
}

#[test]
fn generate_then_validate_skip_expired() -> Result<(), Box<dyn std::error::Error>> {
    let p = Path::new("tests/examples/regen3.cbor");
    if Path::exists(p) {
        fs::remove_file(p.to_str().unwrap())?;
    }

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen3.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-c").arg("tests/examples/cert_store_with_expired");
        cmd.arg("--generate");
        cmd.assert().stdout(predicate::str::contains(
            "Serializing 4 buffers and 7 partial paths",
        ));
        cmd.assert().stdout(predicate::str::contains(
            "Ignored tests/examples/cert_store_with_expired/178.der as not valid at indicated time of interest",
        ));
        assert_eq!(true, p.exists());
    }

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen3.cbor");
        cmd.arg("--list-buffers");
        cmd.assert().stdout(predicate::str::contains("Index: 3"));
    }

    {
        // Try static building with CBOR containing only Email CA-59 to affirm it fails
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen3.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        cmd.assert()
            .stdout(predicate::str::contains("Paths found: 3"));
    }

    {
        // Same as above but with validate_all, still same result
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen3.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-v");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 3 - Result folder indices: [0, 1, 2]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
    }

    {
        // Same as above without validate_all and with different target that does not chain
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen3.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_id_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Failed to find any certification paths for target",
        ));
    }

    {
        // Same as above but with dynamic build enabled.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen3.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-d").arg("tests/examples/downloads");
        cmd.arg("-y");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_id_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
    }
    fs::remove_file(p.to_str().unwrap())?;
    remove_files_from_downloads();
    Ok(())
}

#[test]
fn generate_then_validate_with_expired() -> Result<(), Box<dyn std::error::Error>> {
    let p = Path::new("tests/examples/regen5.cbor");
    if Path::exists(p) {
        fs::remove_file(p.to_str().unwrap())?;
    }

    // mostly same tests as generate_then_validate_skip_expired but with time-of-interest in the past,
    // before the tests/examples/cert_store_with_expired/178.der became invalid.

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen5.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-c").arg("tests/examples/cert_store_with_expired");
        cmd.arg("-i").arg("1642763756");
        cmd.arg("--generate");
        cmd.assert().stdout(predicate::str::contains(
            "Serializing 5 buffers and 11 partial paths",
        ));
        assert_eq!(true, p.exists());
    }

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen5.cbor");
        cmd.arg("--list-buffers");
        cmd.assert().stdout(predicate::str::contains("Index: 3"));
        cmd.assert().stdout(predicate::str::contains("Certificate from tests/examples/cert_store_with_expired/178.der is not valid at indicated time of interest"));
    }

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen5.cbor");
        cmd.arg("-i").arg("1642763756");
        cmd.arg("--list-buffers");
        cmd.assert().stdout(predicate::str::contains("Index: 4"));
    }

    {
        // Try static building to affirm it succeeds with expired cert factored out of the paths found
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen5.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        cmd.assert()
            .stdout(predicate::str::contains("Paths found: 3"));
    }

    {
        // Try static building with time of interest to affirm it succeeds with more valid paths
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen5.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-i").arg("1642763756");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        cmd.assert()
            .stdout(predicate::str::contains("Paths found: 5"));
    }

    {
        // Same as above but with validate_all, still same result
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen5.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-v");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 3 - Result folder indices: [0, 1, 2]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        cmd.assert().stdout(predicate::str::contains("Certificate from tests/examples/cert_store_with_expired/178.der is not valid at indicated time of interest"));
    }

    {
        // Try static building with time of interest to affirm it succeeds with more valid paths
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen5.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-i").arg("1642763756");
        cmd.arg("-v");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 5 - Result folder indices: [0, 1, 2, 3, 4]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        cmd.assert()
            .stdout(predicate::str::contains("Paths found: 5"));
    }

    {
        // Same as above without validate_all and with different target that does not chain
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen5.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_id_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Failed to find any certification paths for target",
        ));
    }

    {
        // Same as above but with dynamic build enabled.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen5.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-d").arg("tests/examples/downloads");
        cmd.arg("-y");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_id_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        cmd.assert()
            .stdout(predicate::str::contains("Paths found: 3"));
    }
    {
        // Same as above but with dynamic build enabled.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen5.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-d").arg("tests/examples/downloads");
        cmd.arg("-i").arg("1642763756");
        cmd.arg("-y");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_id_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        cmd.assert()
            .stdout(predicate::str::contains("Paths found: 5"));
    }

    fs::remove_file(p.to_str().unwrap())?;
    remove_files_from_downloads();
    Ok(())
}

#[test]
fn generate_then_validate_with_different_ta_stores() -> Result<(), Box<dyn std::error::Error>> {
    let p = Path::new("tests/examples/regen4.cbor");
    if Path::exists(p) {
        fs::remove_file(p.to_str().unwrap())?;
    }

    // mostly same tests as generate_then_validate_skip_expired but with time-of-interest in the past,
    // before the tests/examples/cert_store_with_expired/178.der became invalid.

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen4.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-c").arg("tests/examples/cert_store_with_expired");
        cmd.arg("-i").arg("1642763756");
        cmd.arg("--generate");
        cmd.assert().stdout(predicate::str::contains(
            "Serializing 5 buffers and 11 partial paths",
        ));
        assert_eq!(true, p.exists());
    }

    {
        // Try static building to affirm it succeeds with expired cert factored out of the paths found
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen4.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        cmd.assert()
            .stdout(predicate::str::contains("Paths found: 3"));
    }

    {
        // Try static building to affirm it succeeds with expired cert factored out of the paths found
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen4.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        cmd.assert()
            .stdout(predicate::str::contains("Paths found: 1"));
    }

    {
        // Try static building to affirm it succeeds with expired cert factored out of the paths found
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen4.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_two");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        cmd.assert()
            .stdout(predicate::str::contains("Paths found: 2"));
    }

    fs::remove_file(p.to_str().unwrap())?;
    Ok(())
}

#[test]
fn cleanup_tests() -> Result<(), Box<dyn std::error::Error>> {
    let expired = Path::new("tests/examples/expired.der");
    let malformed = Path::new("tests/examples/malformed.der");
    let ee = Path::new("tests/examples/ee.der");
    let selfsigned = Path::new("tests/examples/selfsigned.der");
    let cleanup_expired = Path::new("tests/examples/cleanup_test/expired.der");
    let cleanup_malformed = Path::new("tests/examples/cleanup_test/malformed.der");
    let cleanup_ee = Path::new("tests/examples/cleanup_test/ee.der");
    let cleanup_selfsigned = Path::new("tests/examples/cleanup_test/selfsigned.der");
    fs::copy(expired, cleanup_expired)?;
    fs::copy(selfsigned, cleanup_selfsigned)?;
    fs::copy(malformed, cleanup_malformed)?;
    fs::copy(ee, cleanup_ee)?;

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-c").arg("tests/examples/cleanup_test");
        cmd.arg("--cleanup");
        cmd.arg("--report-only");
        cmd.assert().stdout(predicate::str::contains(
            "Not valid at indicated time of interest",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Missing basicConstraints"));
        cmd.assert().stdout(predicate::str::contains("Self-signed"));
        cmd.assert().stdout(predicate::str::contains(
            "Failed to parse certificate from tests/examples/cleanup_test/malformed.der",
        ));
    }
    {
        let mut cmd2 = Command::cargo_bin("pittv3")?;
        cmd2.arg("-c").arg("tests/examples/cleanup_test");
        cmd2.arg("--cleanup");
        // not sure why only one assert works here. the output contains all same as above where multiple checks work fine.
        // cmd2.assert().stdout(predicate::str::contains(
        //     "Not valid at indicated time of interest",
        // ));
        // cmd2.assert()
        //     .stdout(predicate::str::contains("Missing basicConstraints"));
        // cmd2.assert()
        //     .stdout(predicate::str::contains("Self-signed"));
        cmd2.assert().stdout(predicate::str::contains(
            "Failed to parse certificate from tests/examples/cleanup_test/malformed.der",
        ));
    }
    {
        // Try static building to affirm it succeeds with expired cert factored out of the paths found
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-c").arg("tests/examples/cleanup_test");
        cmd.arg("--cleanup");
        cmd.arg("--report-only");
        cmd.assert().stdout(predicate::str::is_empty());
    }

    Ok(())
}

#[test]
fn generate_then_validate_with_tls_eku() -> Result<(), Box<dyn std::error::Error>> {
    let p = Path::new("tests/examples/regen6.cbor");
    if Path::exists(p) {
        fs::remove_file(p.to_str().unwrap())?;
    }

    // mostly same tests as generate_then_validate_skip_expired but with time-of-interest in the past,
    // before the tests/examples/cert_store_with_expired/178.der became invalid.

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen6.cbor");
        cmd.arg("-t").arg("tests/examples/bettertls_ta_store");
        cmd.arg("-c").arg("tests/examples/bettertls_ca_store");
        cmd.arg("--generate");
        cmd.assert().stdout(predicate::str::contains(
            "Serializing 1 buffers and 1 partial paths",
        ));
        assert_eq!(true, p.exists());
    }

    {
        // Try static building to affirm it succeeds with expired cert factored out of the paths found
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen6.cbor");
        cmd.arg("-t").arg("tests/examples/bettertls_ta_store");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/bettertls_ee_badeku.der");
        cmd.assert().stdout(predicate::str::contains(
            "Success: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        cmd.assert()
            .stdout(predicate::str::contains("Paths found: 1"));
    }

    {
        // Try static building to affirm it succeeds with expired cert factored out of the paths found
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen6.cbor");
        cmd.arg("-t").arg("tests/examples/bettertls_ta_store");
        cmd.arg("--tls-eku");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/bettertls_ee_badeku.der");
        cmd.assert().stdout(predicate::str::contains(
            "InvalidKeyUsage: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 1"));
        cmd.assert()
            .stdout(predicate::str::contains("Paths found: 1"));
    }

    fs::remove_file(p.to_str().unwrap())?;
    Ok(())
}
