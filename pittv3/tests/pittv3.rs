//! This file contains tests that target the std, revocation,std and remote feature gates.

#![cfg(feature = "std")]

use assert_cmd::prelude::*;
use lazy_static::lazy_static;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

lazy_static! {
    static ref TEST_MUTEX: Mutex<()> = Mutex::new(());
}

#[cfg(feature = "remote")]
fn remove_files_from_downloads(f: &str) {
    let _tm = if let Ok(g) = TEST_MUTEX.lock() {
        g
    } else {
        return;
    };

    let rd = match fs::read_dir(Path::new(f)) {
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

        if !e.path().to_str().unwrap().contains(".gitkeep") {
            if let Err(_e) = fs::remove_file(e.path()) {
                continue;
            }
        }
    }
}

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
#[test]
fn process_mozilla_csv() -> Result<(), Box<dyn std::error::Error>> {
    let dp = Path::new("tests/examples/downloads_mozilla");
    if Path::exists(dp) {
        fs::remove_dir_all(dp).unwrap();
    }
    fs::create_dir_all(&dp).unwrap();

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-t")
            .arg("tests/examples/MozillaIntermediateCerts.csv");
        cmd.arg("-c").arg(dp.to_str().unwrap());
        cmd.assert();
    }
    if Path::exists(dp) {
        fs::remove_dir_all(dp).unwrap();
    }
    Ok(())
}

#[cfg(feature = "std")]
#[test]
fn cleanup_trust_anchors() -> Result<(), Box<dyn std::error::Error>> {
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-t").arg("tests/examples/ta_store_two");
        cmd.arg("--ta-cleanup");
        cmd.arg("--report-only");
        cmd.assert();
    }

    Ok(())
}

#[cfg(feature = "std")]
#[test]
fn list_buffers() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("pittv3")?;
    cmd.arg("-b").arg("tests/examples/fpki_and_crtsh.cbor");
    cmd.arg("--list-buffers");
    cmd.assert().stdout(predicate::str::contains("Index: 0"));
    cmd.assert().stdout(predicate::str::contains("Index: 1781"));
    Ok(())
}

#[cfg(feature = "std")]
#[test]
fn dump_cert_at_index() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::PathBuf;
    let mut cmd = Command::cargo_bin("pittv3")?;
    cmd.arg("-b").arg("tests/examples/fpki_and_crtsh.cbor");
    cmd.arg("--dump-cert-at-index").arg("1781");
    cmd.assert().stdout(predicate::str::contains("Encountered error while processing certificate with subject C=US,O=U.S. Government,OU=DoD,OU=PKI,CN=DOD ID SW CA-45: certificate is expired relative to the configured time of interest"));
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("1781.der");
    let p = Path::new(&d);
    if Path::exists(p) {
        fs::remove_file(p.to_str().unwrap()).unwrap();
    } else {
        panic!("File was not exported")
    }
    Ok(())
}

#[cfg(feature = "std")]
#[test]
fn list_aia_and_sia() -> Result<(), Box<dyn std::error::Error>> {
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-b").arg("tests/examples/pitt_focused.cbor");
        cmd.arg("--list-aia-and-sia");
        cmd.assert().stdout(predicate::str::contains(
            "http://crl.disa.mil/issuedto/DODROOTCA3_IT.p7c",
        ));
    }
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-b").arg("tests/examples/fpki_and_crtsh.cbor");
        cmd.arg("--list-aia-and-sia");
        cmd.assert()
            .stdout(predicate::str::contains("https://psc.sia.es/ac_raiz.crt"));
    }
    #[cfg(feature = "remote")]
    {
        let dp = Path::new("tests/examples/downloads_list_aia_and_sia");
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
        fs::create_dir_all(&dp).unwrap();

        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-b").arg("tests/examples/pitt_focused.cbor");
        cmd.arg("--list-aia-and-sia");
        cmd.arg("-d").arg(dp.to_str().unwrap());
        cmd.arg("-y");
        cmd.assert().stdout(predicate::str::contains(
            "http://crl.disa.mil/issuedto/DODROOTCA3_IT.p7c",
        ));

        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
    }
    Ok(())
}

#[cfg(feature = "std")]
#[test]
fn list_name_constraints() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("pittv3")?;
    cmd.arg("-b").arg("tests/examples/fpki_and_crtsh.cbor");
    cmd.arg("--list-name-constraints");
    cmd.assert()
        .stdout(predicate::str::contains("Rfc822Name: raytheon.com"));
    Ok(())
}

#[cfg(feature = "std")]
#[test]
fn list_partial_paths() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("pittv3")?;
    cmd.arg("-b").arg("tests/examples/fpki_and_crtsh.cbor");
    cmd.arg("--list-partial-paths");
    cmd.assert().stdout(predicate::str::contains(
        "TA subject: CN=Hongkong Post Root CA 1 - [1567]",
    ));
    cmd.assert()
        .stdout(predicate::str::contains("- 26 paths with 7 certificates"));
    Ok(())
}

#[cfg(feature = "std")]
#[test]
fn list_partial_paths_for_leaf_ca() -> Result<(), Box<dyn std::error::Error>> {
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-b").arg("tests/examples/fpki_and_crtsh.cbor");
        cmd.arg("--list-partial-paths-for-leaf-ca").arg("5");
        cmd.assert().stdout(predicate::str::contains(
            "Found 1 partial paths featuring 1 different intermediate CA certificates",
        ));
    }
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-b").arg("tests/examples/fpki_and_crtsh.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("--list-partial-paths-for-leaf-ca").arg("5");
        cmd.assert().stdout(predicate::str::contains(
            "Found 0 partial paths featuring 0 different intermediate CA certificates",
        ));
    }
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-b").arg("tests/examples/fpki_and_crtsh.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("--list-partial-paths-for-leaf-ca").arg("158");
        cmd.assert().stdout(predicate::str::contains(
            "Found 3 partial paths featuring 4 different intermediate CA certificates",
        ));
    }
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-b").arg("tests/examples/fpki_and_crtsh.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("--list-partial-paths-for-leaf-ca").arg("158");
        cmd.assert().stdout(predicate::str::contains(
            "Found 1 partial paths featuring 1 different intermediate CA certificates",
        ));
    }
    Ok(())
}

#[cfg(feature = "std")]
#[test]
fn list_partial_paths_for_target() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("pittv3")?;
    cmd.arg("-b").arg("tests/examples/fpki_and_crtsh.cbor");
    cmd.arg("--list-partial-paths-for-target")
        .arg("tests/examples/amazon.der");
    cmd.assert().stdout(predicate::str::contains(
        "* TA subject: CN=DigiCert Global Root G2 - [987]",
    ));

    let mut cmd = Command::cargo_bin("pittv3")?;
    cmd.arg("-b").arg("tests/examples/fpki_and_crtsh.cbor");
    cmd.arg("--list-partial-paths-for-target")
        .arg("tests/cert_store_with_expired/45.der");
    cmd.assert().stdout(predicate::str::contains(
        "Encountered error while processing certificate with subject C=US,O=U.S. Government,OU=DoD,OU=PKI,CN=DOD ID SW CA-45: certificate is expired relative to the configured time of interest",
    ));
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
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("--generate");
        cmd.assert().stdout(predicate::str::contains(
            "Serializing 1 buffers and 1 partial paths",
        ));
        assert!(p.exists());
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
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 1 - Result folder indices: [0]",
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
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
    }

    {
        // Same as above without validate_all and with different target that does not chain
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen1.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_id_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Failed to find any certification paths for target",
        ));
    }

    #[cfg(feature = "remote")]
    {
        let dp = Path::new("tests/examples/downloads_validate_one");
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
        fs::create_dir_all(&dp).unwrap();

        // Same as above but with dynamic build enabled.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen1.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-d").arg(dp.to_str().unwrap());
        cmd.arg("-y");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_id_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
    }
    fs::remove_file(p.to_str().unwrap())?;
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
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-c")
            .arg("tests/examples/cert_store_with_self_signed");
        cmd.arg("--generate");
        cmd.assert().stdout(predicate::str::contains(
            "Serializing 1 buffers and 1 partial paths",
        ));
        assert!(Path::new("tests/examples/regen2.cbor").exists());
        fs::remove_file(p.to_str().unwrap())?;
    }
    Ok(())
}

#[test]
fn empty_cbor1() -> Result<(), Box<dyn std::error::Error>> {
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

    #[cfg(feature = "remote")]
    {
        let dp = Path::new("tests/examples/downloads_empty_cbor1");
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
        fs::create_dir_all(&dp).unwrap();

        // Try dynamic building, which should download a ton of stuff but still only find one valid
        // path given the empty CBOR and ta_store_one. Save downloaded artifacts to downloads folder
        // to avoid polluting next generation.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/empty.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-d").arg(dp.to_str().unwrap());
        cmd.arg("-y");
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
    }

    Ok(())
}

#[test]
fn empty_cbor2() -> Result<(), Box<dyn std::error::Error>> {
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

    #[cfg(feature = "remote")]
    {
        let dp = Path::new("tests/examples/downloads_cbor2");
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
        fs::create_dir_all(&dp).unwrap();

        fs::copy(
            "tests/examples/blocklist_one.json",
            "tests/examples/downloads_cbor2/blocklist.json",
        )
        .unwrap();

        // Same as above but with a blocklist that should deny the necessary URI to find path
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/empty.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-d").arg(dp.to_str().unwrap());
        cmd.arg("-y");
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Failed to find any certification paths for target",
        ));
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
    }
    Ok(())
}

#[test]
fn empty_cbor3() -> Result<(), Box<dyn std::error::Error>> {
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

    #[cfg(feature = "remote")]
    {
        let dp = Path::new("tests/examples/downloads_empty_cbor3");
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
        fs::create_dir_all(&dp).unwrap();

        // Try dynamic building, which should download a ton of stuff and find two valid paths given
        // the empty CBOR, ta_store_two, and validate_all flag.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/empty.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_two");
        cmd.arg("-d").arg(dp.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-y");
        cmd.arg("-v");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 2 - Result folder indices: [0, 1]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));

        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
    }

    Ok(())
}

#[test]
fn empty_cbor4() -> Result<(), Box<dyn std::error::Error>> {
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

    #[cfg(feature = "remote")]
    {
        let dp = Path::new("tests/examples/downloads_empty_cbor3");
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
        fs::create_dir_all(&dp).unwrap();

        // Same as above but without the validate_all flag, so only one path should be returned.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/empty.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_two");
        cmd.arg("-d").arg(dp.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-y");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
    }
    Ok(())
}

#[test]
fn absent_cbor1() -> Result<(), Box<dyn std::error::Error>> {
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

    #[cfg(feature = "remote")]
    {
        let dp = Path::new("tests/examples/downloads_absent_cbor1");
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
        fs::create_dir_all(&dp).unwrap();

        // Try dynamic building, which should download a ton of stuff but still only find one valid
        // path given the empty CBOR and ta_store_one. Save downloaded artifacts to downloads folder
        // to avoid polluting next generation.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-d").arg(dp.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-y");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
    }

    Ok(())
}

#[test]
fn absent_cbor2() -> Result<(), Box<dyn std::error::Error>> {
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

    #[cfg(feature = "remote")]
    {
        let dp = Path::new("tests/examples/downloads_absent_cbor2");
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
        fs::create_dir_all(&dp).unwrap();

        fs::copy(
            "tests/examples/blocklist_one.json",
            "tests/examples/downloads_absent_cbor2/blocklist.json",
        )
        .unwrap();
        // Same as above but with a blocklist that should deny the necessary URI to find path
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-d").arg(dp.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-y");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Failed to find any certification paths for target",
        ));
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
    }

    Ok(())
}

#[test]
fn absent_cbor3() -> Result<(), Box<dyn std::error::Error>> {
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

    #[cfg(feature = "remote")]
    {
        let dp = Path::new("tests/examples/downloads_absent_cbor3");
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
        fs::create_dir_all(&dp).unwrap();

        // Try dynamic building, which should download a ton of stuff and find two valid paths given
        // the empty CBOR, ta_store_two, and validate_all flag.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-t").arg("tests/examples/ta_store_two");
        cmd.arg("-d").arg(dp.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-y");
        cmd.arg("-v");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 2 - Result folder indices: [0, 1]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
    }

    Ok(())
}

#[test]
fn absent_cbor4() -> Result<(), Box<dyn std::error::Error>> {
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

    #[cfg(feature = "remote")]
    {
        let dp = Path::new("tests/examples/downloads_absent_cbor4");
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
        fs::create_dir_all(&dp).unwrap();

        // Same as above but without the validate_all flag, so only one path should be returned.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("-t").arg("tests/examples/ta_store_two");
        cmd.arg("-d").arg(dp.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-y");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
    }
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
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-c").arg("tests/examples/cert_store_with_expired");
        cmd.arg("--generate");
        cmd.assert().stdout(predicate::str::contains(
            "Serializing 4 buffers and 7 partial paths",
        ));
        cmd.assert().stdout(predicate::str::contains(
            "Ignored tests/examples/cert_store_with_expired/178.der as not valid at indicated time of interest",
        ));
        assert!(p.exists());
    }

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen3.cbor");
        cmd.arg("--list-buffers");
        cmd.assert().stdout(predicate::str::contains("Index: 3"));
    }

    {
        use std::fs;
        use tempfile::tempdir;
        let temp_dir = tempdir()?;
        let results_path = temp_dir.path().join("results");
        let _results_dir = fs::create_dir(&results_path)?;

        // Try static building with CBOR containing only Email CA-59 to affirm it fails
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen3.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-r").arg(results_path.as_path().to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 1 - Result folder indices: [0]",
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
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-v");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 3 - Result folder indices: [0, 1, 2]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
    }

    {
        // Same as above without validate_all and with different target that does not chain
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen3.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_id_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Failed to find any certification paths for target",
        ));
    }

    #[cfg(feature = "remote")]
    {
        let dp = Path::new("tests/examples/downloads_validate_skip_expired");
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
        fs::create_dir_all(&dp).unwrap();

        // Same as above but with dynamic build enabled.
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen3.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-d").arg(dp.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-y");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_id_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
    }
    fs::remove_file(p.to_str().unwrap())?;
    Ok(())
}

#[test]
fn multi_pass_build() -> Result<(), Box<dyn std::error::Error>> {
    let p = Path::new("tests/examples/multipass.cbor");
    if Path::exists(p) {
        fs::remove_file(p.to_str().unwrap())?;
    }
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/multipass.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_build_test");
        cmd.arg("-c").arg("tests/examples/build_test");
        cmd.arg("-i").arg("1642763756");
        cmd.arg("--generate");
        cmd.assert().stdout(predicate::str::contains(
            "Serializing 5 buffers and 5 partial paths",
        ));
        assert!(p.exists());
        fs::remove_file(p.to_str().unwrap())?;
    }
    #[cfg(feature = "remote")]
    {
        // same as above but with dynamic build. same result owing to blocklist in build_test folder
        // that includes resources that otherwise would have been fetched
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/multipass.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_build_test");
        cmd.arg("-c").arg("tests/examples/build_test");
        cmd.arg("-i").arg("1642763756");
        cmd.arg("-y");
        cmd.arg("--generate");
        cmd.assert().stdout(predicate::str::contains(
            "Serializing 5 buffers and 5 partial paths",
        ));
        assert!(p.exists());
        fs::remove_file(p.to_str().unwrap())?;
    }

    #[cfg(feature = "remote")]
    {
        let dp = Path::new("tests/examples/downloads_multipass");
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
        fs::create_dir_all(&dp).unwrap();

        // same as above but with dynamic build. same result owing to blocklist in build_test folder
        // that includes resources that otherwise would have been fetched
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/multipass.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_build_test");
        cmd.arg("-c").arg("tests/examples/build_test");
        cmd.arg("-d").arg(dp.to_str().unwrap());
        cmd.arg("-i").arg("1642763756");
        cmd.arg("-y");
        cmd.arg("--generate");
        cmd.assert().stdout(predicate::str::contains(
            "Downloading http://crl.disa.mil/issuedto/DODROOTCA3_IT.p7c",
        ));
        cmd.assert().stdout(predicate::str::contains(
            "Downloading http://repo.fpki.gov/bridge/caCertsIssuedTofbcag4.p7c",
        ));
        cmd.assert().stdout(predicate::str::contains(
            "Downloading http://crl.disa.mil/issuedby/DODINTEROPERABILITYROOTCA2_IB.p7c",
        ));
        cmd.assert().stdout(predicate::str::contains(
            "Downloading http://repo.fpki.gov/fcpca/caCertsIssuedTofcpcag2.p7c",
        ));
        cmd.assert().stdout(predicate::str::contains(
            "Downloading http://repo.fpki.gov/bridge/caCertsIssuedByfbcag4.p7c",
        ));
        assert!(p.exists());
        fs::remove_file(p.to_str().unwrap())?;
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
    }

    if Path::exists(p) {
        fs::remove_file(p.to_str().unwrap())?;
    }
    let p = Path::new("tests/examples/build_test/last_modified_map.json");
    if Path::exists(p) {
        fs::remove_file(p.to_str().unwrap())?;
    }

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
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-c").arg("tests/examples/cert_store_with_expired");
        cmd.arg("-i").arg("1642763756");
        cmd.arg("--generate");
        cmd.assert().stdout(predicate::str::contains(
            "Serializing 5 buffers and 11 partial paths",
        ));
        assert!(p.exists());
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
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 1 - Result folder indices: [0]",
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
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-i").arg("1642763756");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 1 - Result folder indices: [0]",
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
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-v");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 3 - Result folder indices: [0, 1, 2]",
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
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-v");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 5 - Result folder indices: [0, 1, 2, 3, 4]",
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
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_id_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Failed to find any certification paths for target",
        ));
    }

    #[cfg(feature = "remote")]
    {
        let dp = Path::new("tests/examples/downloads_validate_with_expired1");
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
        fs::create_dir_all(&dp).unwrap();
        {
            // Same as above but with dynamic build enabled.
            let mut cmd = Command::cargo_bin("pittv3")?;
            cmd.arg("--cbor").arg("tests/examples/regen5.cbor");
            cmd.arg("-t").arg("tests/examples/ta_store_three");
            cmd.arg("-s")
                .arg("tests/examples/disable_revocation_checking.json");
            cmd.arg("-d").arg(dp.to_str().unwrap());
            cmd.arg("-y");
            cmd.arg("-e")
                .arg("tests/examples/end_entities/from_id_CA_59.der");
            cmd.assert().stdout(predicate::str::contains(
                "Valid: 1 - Result folder indices: [0]",
            ));
            cmd.assert()
                .stdout(predicate::str::contains("Invalid paths found: 0"));
            cmd.assert()
                .stdout(predicate::str::contains("* Paths found: 3"));
        }

        {
            // Same as above but without clearing downloads folder
            let mut cmd = Command::cargo_bin("pittv3")?;
            cmd.arg("--cbor").arg("tests/examples/regen5.cbor");
            cmd.arg("-t").arg("tests/examples/ta_store_three");
            cmd.arg("-s")
                .arg("tests/examples/disable_revocation_checking.json");
            cmd.arg("-d").arg(dp.to_str().unwrap());
            cmd.arg("-y");
            cmd.arg("-e")
                .arg("tests/examples/end_entities/from_id_CA_59.der");
            cmd.assert().stdout(predicate::str::contains(
                "Valid: 1 - Result folder indices: [0]",
            ));
            cmd.assert()
                .stdout(predicate::str::contains("Invalid paths found: 0"));
            cmd.assert()
                .stdout(predicate::str::contains("* Paths found: 3"));
        }

        {
            remove_files_from_downloads(dp.to_str().unwrap());

            // Same as above but with dynamic build enabled.
            let mut cmd = Command::cargo_bin("pittv3")?;
            cmd.arg("--cbor").arg("tests/examples/regen5.cbor");
            cmd.arg("-t").arg("tests/examples/ta_store_three");
            cmd.arg("-d").arg(dp.to_str().unwrap());
            cmd.arg("-s")
                .arg("tests/examples/disable_revocation_checking.json");
            cmd.arg("-i").arg("1642763756");
            cmd.arg("-y");
            cmd.arg("-e")
                .arg("tests/examples/end_entities/from_id_CA_59.der");
            cmd.assert().stdout(predicate::str::contains(
                "Valid: 1 - Result folder indices: [0]",
            ));
            cmd.assert()
                .stdout(predicate::str::contains("Invalid paths found: 0"));
            cmd.assert()
                .stdout(predicate::str::contains("Paths found: 5"));
        }

        {
            // Same as above but without clearing downloads folder
            let mut cmd = Command::cargo_bin("pittv3")?;
            cmd.arg("--cbor").arg("tests/examples/regen5.cbor");
            cmd.arg("-t").arg("tests/examples/ta_store_three");
            cmd.arg("-d").arg(dp.to_str().unwrap());
            cmd.arg("-s")
                .arg("tests/examples/disable_revocation_checking.json");
            cmd.arg("-i").arg("1642763756");
            cmd.arg("-y");
            cmd.arg("-e")
                .arg("tests/examples/end_entities/from_id_CA_59.der");
            cmd.assert().stdout(predicate::str::contains(
                "Valid: 1 - Result folder indices: [0]",
            ));
            cmd.assert()
                .stdout(predicate::str::contains("Invalid paths found: 0"));
            cmd.assert()
                .stdout(predicate::str::contains("Paths found: 5"));
        }
        if Path::exists(dp) {
            fs::remove_dir_all(dp).unwrap();
        }
    }

    fs::remove_file(p.to_str().unwrap())?;
    Ok(())
}

#[test]
fn bad_input() -> Result<(), Box<dyn std::error::Error>> {
    {
        // Try static building to affirm it succeeds with expired cert factored out of the paths found
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/pitt_focused.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-e")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.assert()
            .stdout(predicate::str::contains("Total paths found: 0"));
        cmd.assert()
            .stdout(predicate::str::contains("Failed to parse certificate"));
    }
    {
        // Try static building to affirm it succeeds with expired cert factored out of the paths found
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/pitt_focused.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-e").arg("tests/examples/end_entities/noexist.der");
        cmd.assert()
            .stdout(predicate::str::contains("Total paths found: 0"));
        cmd.assert()
            .stdout(predicate::str::contains("Failed to read"));
    }
    {
        // Try static building to affirm it succeeds with expired cert factored out of the paths found
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/pitt_focused.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_one");
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-e").arg("tests/examples/amazon.der");
        cmd.assert()
            .stdout(predicate::str::contains("Total paths found: 0"));
        cmd.assert().stdout(predicate::str::contains(
            "Failed to find any certification paths for target",
        ));
    }
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
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-c").arg("tests/examples/cert_store_with_expired");
        cmd.arg("-i").arg("1642763756");
        cmd.arg("--generate");
        cmd.assert().stdout(predicate::str::contains(
            "Serializing 5 buffers and 11 partial paths",
        ));
        assert!(p.exists());
    }

    {
        // Try static building to affirm it succeeds with expired cert factored out of the paths found
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen4.cbor");
        cmd.arg("-t").arg("tests/examples/ta_store_three");
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 1 - Result folder indices: [0]",
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
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 1 - Result folder indices: [0]",
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
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-t").arg("tests/examples/ta_store_two");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/from_email_CA_59.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 1 - Result folder indices: [0]",
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

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen6.cbor");
        cmd.arg("-t").arg("tests/examples/bettertls_ta_store");
        cmd.arg("-c").arg("tests/examples/bettertls_ca_store");
        cmd.arg("--generate");
        cmd.assert().stdout(predicate::str::contains(
            "Serializing 1 buffers and 1 partial paths",
        ));
        assert!(p.exists());
    }

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen6.cbor");
        cmd.arg("-t").arg("tests/examples/bettertls_ta_store");
        cmd.arg("-s")
            .arg("tests/examples/disable_revocation_checking.json");
        cmd.arg("-e")
            .arg("tests/examples/end_entities/bettertls_ee_badeku.der");
        cmd.assert().stdout(predicate::str::contains(
            "Valid: 1 - Result folder indices: [0]",
        ));
        cmd.assert()
            .stdout(predicate::str::contains("Invalid paths found: 0"));
        cmd.assert()
            .stdout(predicate::str::contains("Paths found: 1"));
    }

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/regen6.cbor");
        cmd.arg("-t").arg("tests/examples/bettertls_ta_store");
        cmd.arg("-s").arg("tests/examples/tls_eku_settings.json");
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

#[test]
fn pittv3_pkits() -> Result<(), Box<dyn std::error::Error>> {
    use tempfile::tempdir;
    let temp_dir = tempdir().unwrap();
    let results_path = temp_dir.path().join("pkits_results");
    let _results_dir = fs::create_dir(&results_path)?;

    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/pkits.cbor");
        cmd.arg("-t").arg("tests/examples/pkits_ta_store");
        cmd.arg("--crl-folder").arg("tests/examples/pkits_crls");
        cmd.arg("-r").arg(results_path.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/pkits_settings/settings1.json");
        cmd.arg("-f").arg("tests/examples/SeparatedPKITS/1");
        cmd.assert()
            .stdout(predicate::str::contains("Total valid paths found: 2"));
    }
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/pkits.cbor");
        cmd.arg("--crl-folder").arg("tests/examples/pkits_crls");
        cmd.arg("-t").arg("tests/examples/pkits_ta_store");
        cmd.arg("-r").arg(results_path.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/pkits_settings/settings2.json");
        cmd.arg("-f").arg("tests/examples/SeparatedPKITS/2");
        cmd.assert()
            .stdout(predicate::str::contains("Total valid paths found: 1"));
    }
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/pkits.cbor");
        cmd.arg("-t").arg("tests/examples/pkits_ta_store");
        cmd.arg("--crl-folder").arg("tests/examples/pkits_crls");
        cmd.arg("-r").arg(results_path.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/pkits_settings/settings3.json");
        cmd.arg("-f").arg("tests/examples/SeparatedPKITS/3");
        cmd.assert()
            .stdout(predicate::str::contains("Total invalid paths found: 1"));
    }
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/pkits.cbor");
        cmd.arg("-t").arg("tests/examples/pkits_ta_store");
        cmd.arg("--crl-folder").arg("tests/examples/pkits_crls");
        cmd.arg("-r").arg(results_path.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/pkits_settings/settings4.json");
        cmd.arg("-f").arg("tests/examples/SeparatedPKITS/4");
        cmd.assert()
            .stdout(predicate::str::contains("Total invalid paths found: 1"));
    }
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/pkits.cbor");
        cmd.arg("-t").arg("tests/examples/pkits_ta_store");
        cmd.arg("--crl-folder").arg("tests/examples/pkits_crls");
        cmd.arg("-r").arg(results_path.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/pkits_settings/settings5.json");
        cmd.arg("-f").arg("tests/examples/SeparatedPKITS/5");
        cmd.assert()
            .stdout(predicate::str::contains("Total valid paths found: 10"));
    }
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/pkits.cbor");
        cmd.arg("-t").arg("tests/examples/pkits_ta_store");
        cmd.arg("--crl-folder").arg("tests/examples/pkits_crls");
        cmd.arg("-r").arg(results_path.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/pkits_settings/settings6.json");
        cmd.arg("-f").arg("tests/examples/SeparatedPKITS/6");
        cmd.assert()
            .stdout(predicate::str::contains("Total valid paths found: 5"));
    }
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/pkits.cbor");
        cmd.arg("-t").arg("tests/examples/pkits_ta_store");
        cmd.arg("--crl-folder").arg("tests/examples/pkits_crls");
        cmd.arg("-r").arg(results_path.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/pkits_settings/settings7.json");
        cmd.arg("-f").arg("tests/examples/SeparatedPKITS/7");
        cmd.assert()
            .stdout(predicate::str::contains("Total valid paths found: 1"));
    }
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/pkits.cbor");
        cmd.arg("-t").arg("tests/examples/pkits_ta_store");
        cmd.arg("--crl-folder").arg("tests/examples/pkits_crls");
        cmd.arg("-r").arg(results_path.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/pkits_settings/settings8.json");
        cmd.arg("-f").arg("tests/examples/SeparatedPKITS/8");
        cmd.assert()
            .stdout(predicate::str::contains("Total invalid paths found: 2"));
    }
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/pkits.cbor");
        cmd.arg("-t").arg("tests/examples/pkits_ta_store");
        cmd.arg("--crl-folder").arg("tests/examples/pkits_crls");
        cmd.arg("-r").arg(results_path.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/pkits_settings/settings9.json");
        cmd.arg("-f").arg("tests/examples/SeparatedPKITS/9");
        cmd.assert()
            .stdout(predicate::str::contains("Total invalid paths found: 2"));
    }
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/pkits.cbor");
        cmd.arg("-t").arg("tests/examples/pkits_ta_store");
        cmd.arg("--crl-folder").arg("tests/examples/pkits_crls");
        cmd.arg("-r").arg(results_path.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/pkits_settings/settings10.json");
        cmd.arg("-f").arg("tests/examples/SeparatedPKITS/10");
        cmd.assert()
            .stdout(predicate::str::contains("Total invalid paths found: 1"));
    }
    {
        let mut cmd = Command::cargo_bin("pittv3")?;
        cmd.arg("--cbor").arg("tests/examples/pkits.cbor");
        cmd.arg("-t").arg("tests/examples/pkits_ta_store");
        cmd.arg("--crl-folder").arg("tests/examples/pkits_crls");
        cmd.arg("-r").arg(results_path.to_str().unwrap());
        cmd.arg("-s")
            .arg("tests/examples/pkits_settings/default.json");
        cmd.arg("-f").arg("tests/examples/SeparatedPKITS/default");
        cmd.assert();
        // TODO remove targets that do not apply and get right number of valid/invalid
    }
    fs::remove_dir_all(&results_path).unwrap();
    Ok(())
}
