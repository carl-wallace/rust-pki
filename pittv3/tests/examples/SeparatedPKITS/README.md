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

Expected outcomes are in `good.txt` and `bad.txt`, labelled by group, and are checked
target by target by `pittv3_pkits` in `pittv3/tests/pittv3.rs`, apart from the default-group
cases listed in `PKITS_DEFAULT_EXCLUDED` there with their reasons. That test is also the worked
example of driving all of this:

    pittv3 --cbor tests/examples/pkits.cbor \
           -t tests/examples/pkits_ta_store \
           --crl-folder tests/examples/pkits_crls \
           -s tests/examples/pkits_settings/settings3.json \
           -f tests/examples/SeparatedPKITS/3

**Each settings file pins `psTimeOfInterest`** (March 2022), which is what makes these
runs deterministic. At another time of interest, a CRL that does not cover it is left out
of the index (though left on disk), so results can differ; run these with the supplied
settings.
