# PITTv3 wasm settings — sample scenarios

Hand-verified bundles for exercising the wasm app's **Settings** tab. Each scenario is a
`settings.json` (certval `CertificationPathSettings` JSON — the same format the PITTv3 CLI `-s` and
desktop app read) plus the end-entity certificate(s) to validate. Revocation is disabled in every
settings file so results match across the wasm app (which never does revocation) and the CLI/desktop
run offline.

Together they exercise: time of interest, require-explicit-policy + initial-policy-set, inhibit
policy mapping, inhibit anyPolicy, and initial permitted/excluded name-constraint subtrees
(directoryName and iPAddress).

## One-time store setup (Validate tab)

**Scenarios 01–07 and 09 (classic PKITS, RSA)** share one store:
1. Store dropdown → **None (uploaded trust anchors and CA certificates only)**
2. **Trust anchor** upload → `../pkits_ta_store/TrustAnchorRootCertificate.crt`
3. **Intermediate CA** upload → `../pkits.cbor`  (the whole PKITS CA set as a CBOR store)

**Scenario 08 (x509-limbo, ECDSA)** is self-contained and uses its **own** trust anchor
(`08-limbo-ip/limbo_root_ta.pem`); no CA store.

## Running a scenario
1. **Validate** tab: set up the store (above) and upload the scenario's EE cert.
2. **Settings** tab: **Load settings** → the scenario's `settings.json`.
3. **Validate** tab: click **Validate**.

To see a "flip" scenario's *valid* case, reset settings to defaults (or don't load the file) before
validating.

## Scenarios

| # | Setting exercised | EE cert | Expected |
|---|---|---|---|
| 01 | baseline (TOI = 2022 only) | `ValidCertificatePathTest1EE.crt` | **valid** |
| 02 | require explicit policy + matching policy set `2.16.840.1.101.3.2.1.48.1` | `ValidCertificatePathTest1EE.crt` | **valid** |
| 03 | require explicit policy + non-matching policy set `…48.2` | `ValidCertificatePathTest1EE.crt` | **invalid** — NullPolicySet |
| 04 | inhibit policy mapping | `ValidPolicyMappingTest1EE.crt` | **invalid** (valid without the setting) |
| 05 | inhibit anyPolicy | `inhibitAnyPolicyTest3EE.crt` | **invalid** (valid without the setting) |
| 06 | time of interest (reference 2022) vs. an EE not valid until 2047 | `InvalidEEnotBeforeDateTest2EE.crt` | **invalid** — certificate not yet valid |
| 07 | initial **excluded** directoryName subtree `O=Test Certificates 2011,C=US` | `ValidCertificatePathTest1EE.crt` | **invalid** — NameConstraintsViolation |
| 08 | initial **excluded** iPAddress subtree `192.0.2.0/24` vs leaf SAN `192.0.2.1` | `leaf_ip_192.0.2.1_ee.pem` | **invalid** — NameConstraintsViolation (valid without the setting) |
| 09 | initial **excluded** URI subtree `.testcertificates.gov` vs a URI SAN under it | `ValidURInameConstraintsTest34EE.crt` | **invalid** — NameConstraintsViolation (valid without the setting) |

04, 05, 08 and 09 are flips: valid with default settings, invalid once the scenario's one setting is
applied.

## Notes
- **TOI `1647264981` = 2022-03-14** is the PKITS reference time, so the 2010–2030 PKITS certificates
  are within their validity windows.
- **Scenario 06** validates at that 2022 reference time against `InvalidEEnotBeforeDateTest2EE`, whose
  `notBefore` is 2047 — its intermediates are valid at 2022, so only the EE is out of range and the
  result is **invalid** with an `InvalidNotBeforeDate` reason. (Moving the TOI out of range for the
  *whole* chain instead yields "no certification paths found", since no path can be built at all.)
- **Scenario 08 (IP name constraints)** covers the form classic PKITS lacks. The chain is
  `x509-limbo` case `rfc5280::nc::permitted-ipv4-match` (root permits `192.0.2.0/24`, leaf SAN
  `192.0.2.1`): it validates by default, and the excluded-IP setting flips it. The leaf is valid
  1970–2969, so no TOI is needed.
- The wasm app does **no** revocation checking (no CRL/OCSP, no AIA fetch); these scenarios exercise
  basic path validation plus the settings knobs. The same `settings.json` files also load into the
  CLI (`-s`) and desktop app.
- **Scenario 09 (URI name constraints)** validates `ValidURInameConstraintsTest34EE` (URI SAN
  `http://testserver.testcertificates.gov/…`) against the PKITS store; the excluded URI subtree
  `.testcertificates.gov` covers that host, so it flips to invalid. URI matching is now no_std in
  certval (a small hand-rolled host extractor in place of the `url` crate), so the wasm settings UI
  exposes the URI form alongside the other four.
