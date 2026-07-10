#!/usr/bin/env python3
"""
Generate RFC822-in-DN variants of the PKITS RFC822 nameConstraints EE certificates.

For each source EE certificate the rfc822Name in the subjectAltName extension is relocated
into the subject DN as a PKCS#9 emailAddress attribute (and the SAN is dropped), then the
certificate is re-signed with the original issuing CA's private key (recovered from the NIST
PKITS pkcs12 bundle). Everything else -- serial, validity, public key, other extensions -- is
preserved, so the certificate's acceptance now hinges entirely on whether rfc822 name
constraints are applied to an emailAddress attribute carried in the subject DN.

Expected path-validation result is unchanged from the SAN-based original:
  Valid   Test21/23/25 -> SUCCESS
  Invalid Test22/24/26 -> REJECT
"""
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID, ExtensionOID

PKITS = Path("/Users/cwallace/devel/carl-wallace/rust-pki-cert-limbo/certval/tests/examples/PKITS_data_2048/certs")
P12DIR = Path.home() / "devel/redhound/pcp-rs/PKITS_data/pkcs12"
OUT = Path(sys.argv[1])
OUT.mkdir(parents=True, exist_ok=True)
PW = b"password"

# EE test name -> issuing CA p12 basename
EE_TO_CA = {
    "ValidRFC822nameConstraintsTest21EE":   "nameConstraintsRFC822CA1Cert",
    "InvalidRFC822nameConstraintsTest22EE": "nameConstraintsRFC822CA1Cert",
    "ValidRFC822nameConstraintsTest23EE":   "nameConstraintsRFC822CA2Cert",
    "InvalidRFC822nameConstraintsTest24EE": "nameConstraintsRFC822CA2Cert",
    "ValidRFC822nameConstraintsTest25EE":   "nameConstraintsRFC822CA3Cert",
    "InvalidRFC822nameConstraintsTest26EE": "nameConstraintsRFC822CA3Cert",
}

_ca_keys = {}
def ca_key(basename):
    if basename not in _ca_keys:
        key, _cert, _chain = pkcs12.load_key_and_certificates(
            (P12DIR / f"{basename}.p12").read_bytes(), PW)
        _ca_keys[basename] = key
    return _ca_keys[basename]

def rfc822_from_san(cert):
    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    emails = san.get_values_for_type(x509.RFC822Name)
    assert len(emails) == 1, f"expected exactly one rfc822 SAN, got {emails}"
    return emails[0]

def build_variant(ee_name, ca_basename):
    src = x509.load_der_x509_certificate((PKITS / f"{ee_name}.crt").read_bytes())
    email = rfc822_from_san(src)

    # subject DN = original subject + emailAddress attribute (encoded IA5String by cryptography)
    subject = x509.Name(list(src.subject) + [
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)])

    b = (x509.CertificateBuilder()
         .serial_number(src.serial_number)
         .issuer_name(src.issuer)
         .subject_name(subject)
         .public_key(src.public_key())
         .not_valid_before(src.not_valid_before_utc)
         .not_valid_after(src.not_valid_after_utc))
    # copy every extension except the SAN we are relocating
    for ext in src.extensions:
        if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            continue
        b = b.add_extension(ext.value, critical=ext.critical)

    out = b.sign(private_key=ca_key(ca_basename), algorithm=hashes.SHA256())
    new_name = ee_name.replace("RFC822nameConstraints", "RFC822nameConstraintsDN")
    (OUT / f"{new_name}.crt").write_bytes(out.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER))
    print(f"{new_name}.crt  email-in-DN={email}  signer={ca_basename}")

for ee, ca in EE_TO_CA.items():
    build_variant(ee, ca)
print("done")
