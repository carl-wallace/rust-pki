//! Standalone "Check URIs in certificate" diagnostic (the SIA/AIA URI checker).
//!
//! This reproduces the PITTv1/PITTv2 Tools/Analysis "Check URIs in certificate" feature: given a
//! single target certificate (and, optionally, its issuer), every HTTP URI carried in the target's
//! AIA, SIA, CRL DP and freshest-CRL extensions is fetched and evaluated *relative to the target*,
//! independent of certification path processing. It is a reachability + correctness diagnostic, not
//! a path build; nothing here consults a trust anchor store or builds a graph.
//!
//! The algorithm mirrors PITTv2's `CheckAllUrisInCert` (see the legacy C++ in
//! `PITTv2Utils.cpp`). Extensions are processed in order AIA, SIA, CRL DP, freshest CRL, keeping a
//! running list of every certificate fetched from AIA/SIA so a CRL signature can be checked against a
//! discovered issuer when one was not supplied. AIA caIssuers URIs are processed before AIA OCSP
//! URIs so an auto-discovered issuer is available to the OCSP check.
//!
//! Per-URI outcomes follow PITTv2's result taxonomy ([`UriStatus`]). Signature verification, OCSP
//! and CRL retrieval reuse certval's public APIs; certval itself is unchanged.

extern crate alloc;

#[cfg(feature = "remote")]
use alloc::format;
use alloc::string::String;
#[cfg(feature = "remote")]
use alloc::string::ToString;
#[cfg(feature = "remote")]
use alloc::vec;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::report::CertSummary;

/// Which extension carried a URI. Rendered in the "Extension" column of the results grid.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum UriExtension {
    /// authorityInfoAccess caIssuers
    Aia,
    /// authorityInfoAccess OCSP
    Ocsp,
    /// subjectInfoAccess caRepository
    Sia,
    /// cRLDistributionPoints
    CrlDp,
    /// freshestCRL
    FreshestCrl,
}

impl UriExtension {
    /// Short label matching the PITTv2 "Extension" column.
    pub fn label(&self) -> &'static str {
        match self {
            UriExtension::Aia => "AIA",
            UriExtension::Ocsp => "AIA",
            UriExtension::Sia => "SIA",
            UriExtension::CrlDp => "CRL DP",
            UriExtension::FreshestCrl => "Freshest CRL",
        }
    }
}

/// Per-URI outcome, mirroring PITTv2's `URIResult` enum. The stringified names match PITTv2's result
/// column so existing muscle memory (and logs) carry over.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum UriStatus {
    /// URI could not be retrieved.
    NotAvailable,
    /// Retrieved artifact does not correspond to the target certificate.
    IncorrectData,
    /// Retrieved artifact corresponds to the target certificate.
    CorrectData,
    /// Retrieved certificate collection includes a self-signed certificate.
    Warning,
    /// AIA/SIA carried a URI under an access method this checker does not handle.
    UnknownAccessMethod,
    /// URI host is on the configured blocklist.
    BlacklistedHost,
    /// A CRL was obtained but not inspected because no issuer certificate was available.
    CrlNotCheckedNoIssuerCert,
    /// OCSP responder certificate does not share a policy with the target certificate.
    ResponderCertPolicyError,
    /// Target has no cRLDistributionPoints extension (and is not a trust anchor).
    WarningMissingCrlDp,
    /// Target has no authorityInfoAccess extension (and is not a trust anchor).
    WarningMissingAia,
}

impl UriStatus {
    /// PITTv2-compatible result string.
    pub fn label(&self) -> &'static str {
        match self {
            UriStatus::NotAvailable => "URI_NOT_AVAILABLE",
            UriStatus::IncorrectData => "URI_INCORRECT_DATA",
            UriStatus::CorrectData => "URI_CORRECT_DATA",
            UriStatus::Warning => "URI_WARNING",
            UriStatus::UnknownAccessMethod => "URI_INCORRECT_ACCESS_METHOD",
            UriStatus::BlacklistedHost => "URI_BLACKLISTED_HOST",
            UriStatus::CrlNotCheckedNoIssuerCert => "URI_CRL_NOT_CHECKED_NO_ISSUER_CERT",
            UriStatus::ResponderCertPolicyError => "URI_RESPONDER_CERT_POLICY_ERROR",
            UriStatus::WarningMissingCrlDp => "URI_WARNING_MISSING_CRLDP",
            UriStatus::WarningMissingAia => "URI_WARNING_MISSING_AIA",
        }
    }
}

/// One row of the results grid: URI, extension it came from, outcome, and elapsed fetch time.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UriCheckResult {
    /// The URI checked (or a synthetic `<AIA URI not found>` / `<CRL DP URI not found>` marker).
    pub uri: String,
    /// Extension that carried the URI.
    pub extension: UriExtension,
    /// Outcome of the check.
    pub status: UriStatus,
    /// Elapsed time, in milliseconds, spent retrieving the URI (0 for synthetic rows).
    pub timing_ms: u64,
    /// Optional human-readable detail (e.g. number of certs fetched, error text).
    pub detail: Option<String>,
}

/// Full result of a "Check URIs in certificate" run over one target certificate. Serde-serializable
/// so the CLI, desktop GUI and any future frontend share one representation.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UriCheckReport {
    /// Summary of the target certificate; empty when the target could not be parsed.
    pub target: CertSummary,
    /// Summary of the issuer certificate, when supplied or auto-discovered.
    pub issuer: Option<CertSummary>,
    /// True when the issuer was auto-discovered from an AIA caIssuers pointer rather than supplied.
    pub issuer_auto_discovered: bool,
    /// One row per URI checked, in processing order (AIA, SIA, CRL DP, freshest CRL).
    pub results: Vec<UriCheckResult>,
    /// Fatal error (e.g. the target certificate failed to parse); when set, `results` is empty.
    pub error: Option<String>,
}

impl UriCheckReport {
    /// Constructs a report carrying only a fatal error.
    pub fn failed(message: impl Into<String>) -> Self {
        UriCheckReport {
            error: Some(message.into()),
            ..Default::default()
        }
    }

    /// Renders the report as a fixed-width table (URI | Result | Timing (ms) | Extension), matching
    /// the columns of the PITTv2 "Check URIs" dialog. Shared by the CLI and any text frontend.
    pub fn to_table_string(&self) -> String {
        use core::fmt::Write as _;

        let mut out = String::new();
        let _ = writeln!(out, "Target: {}", self.target.subject);
        if let Some(iss) = &self.issuer {
            let disc = if self.issuer_auto_discovered {
                " (auto-discovered)"
            } else {
                ""
            };
            let _ = writeln!(out, "Issuer: {}{}", iss.subject, disc);
        }
        if let Some(err) = &self.error {
            let _ = writeln!(out, "Error: {err}");
            return out;
        }
        if self.results.is_empty() {
            let _ = writeln!(out, "No URIs found to check.");
            return out;
        }

        let uri_w = self
            .results
            .iter()
            .map(|r| r.uri.len())
            .max()
            .unwrap_or(3)
            .max(3);
        let res_w = self
            .results
            .iter()
            .map(|r| r.status.label().len())
            .max()
            .unwrap_or(6)
            .max(6);
        let _ = writeln!(
            out,
            "{:<uri_w$}  {:<res_w$}  {:>11}  Extension",
            "URI",
            "Result",
            "Timing (ms)",
            uri_w = uri_w,
            res_w = res_w
        );
        for r in &self.results {
            let _ = writeln!(
                out,
                "{:<uri_w$}  {:<res_w$}  {:>11}  {}",
                r.uri,
                r.status.label(),
                r.timing_ms,
                r.extension.label(),
                uri_w = uri_w,
                res_w = res_w
            );
        }
        out
    }
}

#[cfg(feature = "remote")]
pub use remote_impl::{check_uris_from_bytes, check_uris_in_cert};

#[cfg(feature = "remote")]
mod remote_impl {
    use super::*;
    use core::time::Duration;
    use std::time::Instant;

    use certval::*;

    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use const_oid::db::rfc5912::{
        ID_AD_CA_ISSUERS, ID_AD_CA_REPOSITORY, ID_AD_OCSP, ID_CE_CRL_DISTRIBUTION_POINTS,
        ID_CE_FRESHEST_CRL, ID_PE_AUTHORITY_INFO_ACCESS, ID_PE_SUBJECT_INFO_ACCESS,
    };
    use der::{Decode, Encode};
    use log::debug;
    use x509_cert::crl::CertificateList;
    use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};

    // A single 10 second per-request timeout mirrors certval's remote fetch client.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

    /// Convenience entry point that builds an RFC 5280 [`PkiEnvironment`] and default settings, then
    /// runs [`check_uris_in_cert`]. Both the CLI and GUI use this so neither has to construct a PKI
    /// environment itself. `time_of_interest` is the usual Unix-seconds value (0 disables the
    /// validity check). Signature verification requires the `rsa`/`eddsa`/`pqc` crypto features to be
    /// enabled; without them every verification is treated as a failure.
    pub async fn check_uris_from_bytes(
        target_der: &[u8],
        issuer_der: Option<&[u8]>,
        auto_discover: bool,
        time_of_interest: u64,
        blocklist: &[String],
    ) -> UriCheckReport {
        let mut cps = CertificationPathSettings::default();
        if let Ok(toi) = TimeOfInterest::from_unix_secs(time_of_interest) {
            cps.set_time_of_interest(toi);
        }
        let mut pe = PkiEnvironment::default();
        pe.populate_5280_pki_environment();
        check_uris_in_cert(&pe, &cps, target_der, issuer_der, auto_discover, blocklist).await
    }

    /// Checks every HTTP URI carried in the target certificate's AIA, SIA, CRL DP and freshest-CRL
    /// extensions and returns a per-URI reachability + correctness report modeled on PITTv2's
    /// "Check URIs in certificate" feature.
    ///
    /// `issuer_der`, when present, enables CRL-signature verification and OCSP checking. When it is
    /// absent and `auto_discover` is true, the first AIA caIssuers pointer that yields the issuer is
    /// adopted for those checks. `blocklist` names hosts/URIs to skip (reported as blocklisted).
    pub async fn check_uris_in_cert(
        pe: &PkiEnvironment,
        cps: &CertificationPathSettings,
        target_der: &[u8],
        issuer_der: Option<&[u8]>,
        auto_discover: bool,
        blocklist: &[String],
    ) -> UriCheckReport {
        let target = match PDVCertificate::try_from(target_der) {
            Ok(c) => c,
            Err(e) => {
                return UriCheckReport::failed(format!("failed to parse target certificate: {e:?}"))
            }
        };

        let mut issuer = match issuer_der {
            Some(der) => match PDVCertificate::try_from(der) {
                Ok(c) => Some(c),
                Err(e) => {
                    return UriCheckReport::failed(format!(
                        "failed to parse issuer certificate: {e:?}"
                    ))
                }
            },
            None => None,
        };
        let issuer_supplied = issuer.is_some();

        let client = match reqwest::Client::builder().build() {
            Ok(c) => c,
            Err(e) => return UriCheckReport::failed(format!("failed to build HTTP client: {e}")),
        };

        let mut report = UriCheckReport {
            target: CertSummary::from_cert(&target),
            ..Default::default()
        };

        // Every certificate fetched from AIA/SIA, reused to verify a CRL signature when no issuer
        // was supplied (mirrors PITTv2's running certList).
        let mut cert_list: Vec<PDVCertificate> = vec![];

        let is_ta = pe.get_trust_anchor_for_target(&target).is_ok();

        // ---- AIA ----------------------------------------------------------------------------
        let (ca_issuers, ocsp) = collect_aia(&target);
        if ca_issuers.is_empty() && ocsp.is_empty() && !is_ta {
            report.results.push(UriCheckResult {
                uri: "<AIA URI not found>".to_string(),
                extension: UriExtension::Aia,
                status: UriStatus::WarningMissingAia,
                timing_ms: 0,
                detail: None,
            });
        }
        for uri in ca_issuers {
            let r = check_uri_certificate(
                pe,
                &client,
                &uri,
                &target,
                false,
                &mut issuer,
                auto_discover,
                UriExtension::Aia,
                blocklist,
                cps,
                &mut cert_list,
            )
            .await;
            report.results.push(r);
        }
        for uri in ocsp {
            let r =
                check_uri_ocsp(pe, &client, &uri, &target, issuer.as_ref(), blocklist, cps).await;
            report.results.push(r);
        }

        // ---- SIA ----------------------------------------------------------------------------
        for uri in collect_sia(&target) {
            let r = check_uri_certificate(
                pe,
                &client,
                &uri,
                &target,
                true,
                &mut issuer,
                auto_discover,
                UriExtension::Sia,
                blocklist,
                cps,
                &mut cert_list,
            )
            .await;
            report.results.push(r);
        }

        // ---- CRL DP -------------------------------------------------------------------------
        let crl_dps = collect_crl_dps(&target, ID_CE_CRL_DISTRIBUTION_POINTS);
        if crl_dps.is_empty() && !is_ta {
            report.results.push(UriCheckResult {
                uri: "<CRL DP URI not found>".to_string(),
                extension: UriExtension::CrlDp,
                status: UriStatus::WarningMissingCrlDp,
                timing_ms: 0,
                detail: None,
            });
        }
        for uri in crl_dps {
            let r = check_uri_crl(
                pe,
                &client,
                &uri,
                &target,
                issuer.as_ref(),
                auto_discover,
                UriExtension::CrlDp,
                blocklist,
                &cert_list,
            )
            .await;
            report.results.push(r);
        }

        // ---- freshest CRL -------------------------------------------------------------------
        for uri in collect_crl_dps(&target, ID_CE_FRESHEST_CRL) {
            let r = check_uri_crl(
                pe,
                &client,
                &uri,
                &target,
                issuer.as_ref(),
                auto_discover,
                UriExtension::FreshestCrl,
                blocklist,
                &cert_list,
            )
            .await;
            report.results.push(r);
        }

        if let Some(iss) = &issuer {
            report.issuer = Some(CertSummary::from_cert(iss));
            report.issuer_auto_discovered = !issuer_supplied;
        }

        report
    }

    /// Collects http(s) URIs from AIA, split into (caIssuers, OCSP) queues.
    fn collect_aia(cert: &PDVCertificate) -> (Vec<String>, Vec<String>) {
        let mut ca_issuers = vec![];
        let mut ocsp = vec![];
        if let Ok(Some(PDVExtension::AuthorityInfoAccessSyntax(aia))) =
            cert.get_extension(&ID_PE_AUTHORITY_INFO_ACCESS)
        {
            for ad in &aia.0 {
                if let GeneralName::UniformResourceIdentifier(uri) = &ad.access_location {
                    let s = uri.to_string();
                    if !s.starts_with("http") {
                        continue;
                    }
                    if ad.access_method == ID_AD_CA_ISSUERS {
                        push_unique(&mut ca_issuers, s);
                    } else if ad.access_method == ID_AD_OCSP {
                        push_unique(&mut ocsp, s);
                    }
                }
            }
        }
        (ca_issuers, ocsp)
    }

    /// Collects http(s) caRepository URIs from SIA.
    fn collect_sia(cert: &PDVCertificate) -> Vec<String> {
        let mut uris = vec![];
        if let Ok(Some(PDVExtension::SubjectInfoAccessSyntax(sia))) =
            cert.get_extension(&ID_PE_SUBJECT_INFO_ACCESS)
        {
            for ad in &sia.0 {
                if ad.access_method != ID_AD_CA_REPOSITORY {
                    continue;
                }
                if let GeneralName::UniformResourceIdentifier(uri) = &ad.access_location {
                    let s = uri.to_string();
                    if s.starts_with("http") {
                        push_unique(&mut uris, s);
                    }
                }
            }
        }
        uris
    }

    /// Collects http(s) full-name URIs from a cRLDistributionPoints-shaped extension (CRL DP or
    /// freshestCRL, which share a structure).
    fn collect_crl_dps(cert: &PDVCertificate, oid: const_oid::ObjectIdentifier) -> Vec<String> {
        let mut uris = vec![];
        let dps = match cert.get_extension(&oid) {
            Ok(Some(PDVExtension::CrlDistributionPoints(dps))) => dps.0.clone(),
            Ok(Some(PDVExtension::FreshestCrl(dps))) => dps.0.clone(),
            _ => return uris,
        };
        for dp in &dps {
            if let Some(DistributionPointName::FullName(gns)) = &dp.distribution_point {
                for gn in gns {
                    if let GeneralName::UniformResourceIdentifier(uri) = gn {
                        let s = uri.to_string();
                        if s.starts_with("http") {
                            push_unique(&mut uris, s);
                        }
                    }
                }
            }
        }
        uris
    }

    fn push_unique(v: &mut Vec<String>, s: String) {
        if !v.contains(&s) {
            v.push(s);
        }
    }

    fn is_blocklisted(uri: &str, blocklist: &[String]) -> bool {
        blocklist.iter().any(|b| uri.contains(b.as_str()))
    }

    /// Fetches raw bytes for a URI, returning (success, body). Success is false on any transport
    /// error, non-2xx status, or an HTML error page.
    async fn http_get(client: &reqwest::Client, uri: &str) -> (bool, Vec<u8>) {
        let resp = match client.get(uri).timeout(REQUEST_TIMEOUT).send().await {
            Ok(r) => r,
            Err(e) => {
                debug!("fetch failed for {uri}: {e}");
                return (false, vec![]);
            }
        };
        if !resp.status().is_success() {
            return (false, vec![]);
        }
        let is_html = resp
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.starts_with("text/html"))
            .unwrap_or(false);
        if is_html {
            return (false, vec![]);
        }
        match resp.bytes().await {
            Ok(b) => (true, b.to_vec()),
            Err(e) => {
                debug!("body read failed for {uri}: {e}");
                (false, vec![])
            }
        }
    }

    /// Parses fetched bytes into certificates, handling a single DER certificate, a PEM bundle, or a
    /// degenerate certs-only PKCS#7 SignedData (`.p7c`, common for SIA caRepository).
    fn parse_certs(bytes: &[u8]) -> Vec<PDVCertificate> {
        let mut out = vec![];

        if let Ok(cert) = PDVCertificate::try_from(bytes) {
            out.push(cert);
            return out;
        }

        // PEM bundle (possibly multiple CERTIFICATE blocks).
        if let Ok(text) = core::str::from_utf8(bytes) {
            if text.contains("-----BEGIN CERTIFICATE-----") {
                for block in text.split("-----BEGIN CERTIFICATE-----").skip(1) {
                    if let Some(end) = block.find("-----END CERTIFICATE-----") {
                        let b64: String = block[..end]
                            .chars()
                            .filter(|c| !c.is_whitespace())
                            .collect();
                        if let Ok(der) = base64_decode(&b64) {
                            if let Ok(cert) = PDVCertificate::try_from(der.as_slice()) {
                                out.push(cert);
                            }
                        }
                    }
                }
                if !out.is_empty() {
                    return out;
                }
            }
        }

        // Degenerate certs-only PKCS#7 SignedData.
        if let Ok(ci) = ContentInfo::from_der(bytes) {
            if let Ok(content) = ci.content.to_der() {
                if let Ok(sd) = SignedData::from_der(&content) {
                    if let Some(certs) = sd.certificates {
                        for choice in certs.0.iter() {
                            if let Ok(der) = choice.to_der() {
                                // CertificateChoices re-encodes to the inner certificate DER for the
                                // plain Certificate variant; fall back to trying it directly.
                                if let Ok(cert) = PDVCertificate::try_from(der.as_slice()) {
                                    out.push(cert);
                                }
                            }
                        }
                    }
                }
            }
        }

        out
    }

    /// Minimal standard base64 decoder for PEM bodies (avoids pulling in a new dependency).
    fn base64_decode(s: &str) -> core::result::Result<Vec<u8>, ()> {
        fn val(c: u8) -> core::result::Result<u8, ()> {
            match c {
                b'A'..=b'Z' => Ok(c - b'A'),
                b'a'..=b'z' => Ok(c - b'a' + 26),
                b'0'..=b'9' => Ok(c - b'0' + 52),
                b'+' => Ok(62),
                b'/' => Ok(63),
                _ => Err(()),
            }
        }
        let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
        let mut out = vec![];
        for chunk in bytes.chunks(4) {
            let mut buf = [0u8; 4];
            for (i, &b) in chunk.iter().enumerate() {
                buf[i] = val(b)?;
            }
            match chunk.len() {
                4 => {
                    out.push((buf[0] << 2) | (buf[1] >> 4));
                    out.push((buf[1] << 4) | (buf[2] >> 2));
                    out.push((buf[2] << 6) | buf[3]);
                }
                3 => {
                    out.push((buf[0] << 2) | (buf[1] >> 4));
                    out.push((buf[1] << 4) | (buf[2] >> 2));
                }
                2 => out.push((buf[0] << 2) | (buf[1] >> 4)),
                _ => return Err(()),
            }
        }
        Ok(out)
    }

    /// Returns true if `issuer`'s public key verifies `subject`'s signature.
    fn verifies(pe: &PkiEnvironment, subject: &PDVCertificate, issuer: &PDVCertificate) -> bool {
        let defer = match DeferDecodeSigned::from_der(subject.as_bytes()) {
            Ok(d) => d,
            Err(_) => return false,
        };
        let spki = issuer.decoded().tbs_certificate().subject_public_key_info();
        pe.verify_signature_message(
            pe,
            &defer.tbs_field,
            subject.decoded().signature().raw_bytes(),
            subject.decoded().tbs_certificate().signature(),
            spki,
        )
        .is_ok()
    }

    fn any_self_signed(pe: &PkiEnvironment, certs: &[PDVCertificate]) -> bool {
        certs.iter().any(|c| is_self_signed(pe, c))
    }

    /// PITTv2 `CheckCerts`: does the fetched collection have the right relationship to the target?
    /// For SIA the target is the issuing CA (one fetched cert must be signed by it); for AIA the
    /// target is the subject (one fetched non-self-signed cert must sign it, which is then adopted as
    /// the issuer when auto-discovering).
    fn check_certs(
        pe: &PkiEnvironment,
        certs: &[PDVCertificate],
        target: &PDVCertificate,
        from_sia: bool,
        issuer: &mut Option<PDVCertificate>,
        auto_discover: bool,
    ) -> bool {
        for (i, c) in certs.iter().enumerate() {
            if from_sia {
                if verifies(pe, c, target) {
                    return true;
                }
            } else {
                let self_signed = is_self_signed(pe, c);
                if !self_signed && verifies(pe, target, c) {
                    if issuer.is_none() && auto_discover {
                        *issuer = Some(c.clone());
                    }
                    return true;
                } else if i + 1 == certs.len() && self_signed && verifies(pe, target, c) {
                    // A lone self-signed match is adopted as the issuer for later CRL/OCSP checks but
                    // does not by itself count as correct data (it becomes URI_WARNING).
                    if issuer.is_none() && auto_discover {
                        *issuer = Some(c.clone());
                    }
                }
            }
        }
        false
    }

    #[allow(clippy::too_many_arguments)]
    async fn check_uri_certificate(
        pe: &PkiEnvironment,
        client: &reqwest::Client,
        uri: &str,
        target: &PDVCertificate,
        from_sia: bool,
        issuer: &mut Option<PDVCertificate>,
        auto_discover: bool,
        extension: UriExtension,
        blocklist: &[String],
        _cps: &CertificationPathSettings,
        cert_list: &mut Vec<PDVCertificate>,
    ) -> UriCheckResult {
        if is_blocklisted(uri, blocklist) {
            return row(uri, extension, UriStatus::BlacklistedHost, 0, None);
        }

        let start = Instant::now();
        let (ok, bytes) = http_get(client, uri).await;
        let timing_ms = start.elapsed().as_millis() as u64;
        let certs = parse_certs(&bytes);

        let all_good = check_certs(pe, &certs, target, from_sia, issuer, auto_discover);
        let status = if all_good {
            if any_self_signed(pe, &certs) {
                UriStatus::Warning
            } else {
                UriStatus::CorrectData
            }
        } else if !certs.is_empty() {
            UriStatus::IncorrectData
        } else if !ok {
            UriStatus::NotAvailable
        } else {
            UriStatus::IncorrectData
        };

        let detail = Some(format!("{} certificate(s) retrieved", certs.len()));
        for c in certs {
            if !cert_list.iter().any(|e| e.as_bytes() == c.as_bytes()) {
                cert_list.push(c);
            }
        }
        row(uri, extension, status, timing_ms, detail)
    }

    async fn check_uri_ocsp(
        pe: &PkiEnvironment,
        client: &reqwest::Client,
        uri: &str,
        target: &PDVCertificate,
        issuer: Option<&PDVCertificate>,
        blocklist: &[String],
        cps: &CertificationPathSettings,
    ) -> UriCheckResult {
        if is_blocklisted(uri, blocklist) {
            return row(uri, UriExtension::Ocsp, UriStatus::BlacklistedHost, 0, None);
        }

        let issuer = match issuer {
            Some(i) => i,
            None => {
                return row(
                    uri,
                    UriExtension::Ocsp,
                    UriStatus::CrlNotCheckedNoIssuerCert,
                    0,
                    Some("no issuer certificate available for OCSP".to_string()),
                )
            }
        };

        let _ = client; // OCSP transport is handled inside certval's OCSP client.
        let mut cpr = CertificationPathResults::new();
        let start = Instant::now();
        let sent = send_ocsp_request(pe, cps, uri, target, issuer.decoded(), &mut cpr, 0).await;
        let timing_ms = start.elapsed().as_millis() as u64;

        let status = if sent.is_ok() {
            UriStatus::CorrectData
        } else {
            UriStatus::IncorrectData
        };
        let detail = sent.err().map(|e| format!("{e:?}"));
        row(uri, UriExtension::Ocsp, status, timing_ms, detail)
    }

    /// PITTv2 `CrlIsCompatiableWithCert` (issuer-name-scope + optional signature verification). The
    /// full issuingDistributionPoint scope validation is not reproduced here; the common no-IDP path
    /// (CRL issuer name equals the certificate's issuer name) plus signature verification against a
    /// known issuer is applied.
    fn crl_compatible(
        pe: &PkiEnvironment,
        crl: &CertificateList,
        target: &PDVCertificate,
        issuer: Option<&PDVCertificate>,
    ) -> bool {
        if !compare_names(
            &crl.tbs_cert_list.issuer,
            target.decoded().tbs_certificate().issuer(),
        ) {
            return false;
        }
        if let Some(iss) = issuer {
            let der = match crl.to_der() {
                Ok(d) => d,
                Err(_) => return false,
            };
            let defer = match DeferDecodeSigned::from_der(&der) {
                Ok(d) => d,
                Err(_) => return false,
            };
            let spki = iss.decoded().tbs_certificate().subject_public_key_info();
            return pe
                .verify_signature_message(
                    pe,
                    &defer.tbs_field,
                    crl.signature.raw_bytes(),
                    &crl.signature_algorithm,
                    spki,
                )
                .is_ok();
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    async fn check_uri_crl(
        pe: &PkiEnvironment,
        client: &reqwest::Client,
        uri: &str,
        target: &PDVCertificate,
        issuer: Option<&PDVCertificate>,
        auto_discover: bool,
        extension: UriExtension,
        blocklist: &[String],
        cert_list: &[PDVCertificate],
    ) -> UriCheckResult {
        if is_blocklisted(uri, blocklist) {
            return row(uri, extension, UriStatus::BlacklistedHost, 0, None);
        }

        let start = Instant::now();
        let (ok, bytes) = http_get(client, uri).await;
        let timing_ms = start.elapsed().as_millis() as u64;

        let crl = CertificateList::from_der(&bytes);
        let status = match crl {
            Ok(crl) => {
                let compatible = if let Some(iss) = issuer {
                    crl_compatible(pe, &crl, target, Some(iss))
                } else if !cert_list.is_empty() && auto_discover {
                    cert_list
                        .iter()
                        .any(|c| crl_compatible(pe, &crl, target, Some(c)))
                } else {
                    crl_compatible(pe, &crl, target, None)
                };
                if compatible {
                    UriStatus::CorrectData
                } else if issuer.is_some() {
                    UriStatus::IncorrectData
                } else {
                    UriStatus::CrlNotCheckedNoIssuerCert
                }
            }
            Err(_) => {
                if !ok {
                    UriStatus::NotAvailable
                } else {
                    UriStatus::IncorrectData
                }
            }
        };
        row(uri, extension, status, timing_ms, None)
    }

    fn row(
        uri: &str,
        extension: UriExtension,
        status: UriStatus,
        timing_ms: u64,
        detail: Option<String>,
    ) -> UriCheckResult {
        UriCheckResult {
            uri: uri.to_string(),
            extension,
            status,
            timing_ms,
            detail,
        }
    }
}
