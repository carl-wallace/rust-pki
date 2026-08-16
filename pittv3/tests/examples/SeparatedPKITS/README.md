# SeparatedPKITS

The NIST PKITS end entity certificates, split into one folder per **settings group** —
`default` plus `1` through `10` — matching the groups NIST defines in PKITS §4.8.1, §4.10.1
and §4.12.3, where the same certificate is meant to be validated under different initial
policy inputs.

The settings that go with each folder are the sibling directory:

| this folder | its settings |
|---|---|
| `SeparatedPKITS/default` | `../pkits_settings/default.json` |
| `SeparatedPKITS/1` … `10` | `../pkits_settings/settings1.json` … `settings10.json` |

The rest of the material, also siblings: `../pkits_ta_store` (trust anchors),
`../pkits_crls` (CRLs), `../pkits.cbor` (a prebuilt graph; a folder of CA certificates
also works as a validation input).

Expected outcomes are in `good.txt` and `bad.txt`, labelled by group, and are asserted
per group by `pkits_separated` in `pittv3/tests/pittv3.rs`, which is also the worked
example of driving all of this:

    pittv3 --cbor tests/examples/pkits.cbor \
           -t tests/examples/pkits_ta_store \
           --crl-folder tests/examples/pkits_crls \
           -s tests/examples/pkits_settings/settings3.json \
           -f tests/examples/SeparatedPKITS/3

**Each settings file pins `psTimeOfInterest`** (March 2022), which is what makes these
runs deterministic — and what keeps `pkits_crls` intact. Validating this material at the
*current* time instead prunes CRLs: a CRL that is stale at the time of interest is
deleted from the folder given to `--crl-folder` (see `CrlSourceFolders::index_crls`), so
run these with the supplied settings, or point the CRL folder at a copy.
