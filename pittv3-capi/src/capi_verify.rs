//! The Windows half: driving `CertGetCertificateChain` and `CertVerifyCertificateChainPolicy`, and
//! turning what they leave behind into the types in [`types`](crate::types).
//!
//! This is the only module in the workspace that contains `unsafe`, and the only one that names the
//! `windows` crate. Everything it does is confined to one call tree under [`verify`], which takes
//! bytes and returns owned data: no handle, pointer or borrowed Win32 memory escapes it.
//!
//! # Lifetimes are the whole difficulty
//!
//! Every pointer the chain engine hands back — each `CERT_CONTEXT`, each `CERT_REVOCATION_CRL_INFO`,
//! each `pwszExtendedErrorInfo` — is owned by the `CERT_CHAIN_CONTEXT` and dies with it. PITTv2 dealt
//! with that by never freeing the chain context: it pushed each one onto `m_panel->m_pChainContext`
//! and let the panel hold them for the life of the window, because its grid rows held raw
//! `PCERT_SIMPLE_CHAIN` pointers into them. That is why its results could not outlive the panel and
//! why a run leaked a chain context per target.
//!
//! Here everything is copied out — `Vec<u8>` for encodings, `String` for text — before the guards
//! at the end of [`verify`] free anything, so the returned [`CapiVerification`] owns itself and the
//! Win32 allocations are gone by the time the function returns.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ptr;
use std::ffi::CString;

use certval::source::ta_source::buffer_to_hex;
use certval::{name_to_string, PDVCertificate};
use der::Decode;
use log::{debug, warn};
use pittv3_lib::report::CertSummary;
use windows::core::{PCSTR, PSTR};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::Security::Cryptography::*;
use x509_cert::certificate::Rfc5280;
use x509_cert::crl::CertificateList;

use crate::status::{CapiError, CapiTrustStatus};
use crate::types::{
    filetime_to_string, CapiChain, CapiCrlEntry, CapiCrlInfo, CapiElement, CapiOptions,
    CapiRevocationInfo, CapiVerification, CapiVerifyError, ChainPolicy, RevocationChecking,
    UsageMatch,
};

/// Both encodings, which is what PITTv2 passed and what every CAPI sample passes: a certificate is
/// DER either way, and naming both costs nothing.
const ENCODINGS: CERT_QUERY_ENCODING_TYPE =
    CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0);

/// Builds and validates a certification path for `target_der` using the Windows chain engine.
///
/// Returns [`Ok`] whenever the engine produced a verdict, including an unfavorable one — a failed
/// path is a [`CapiVerification`] with [`validated`](CapiVerification::validated) false, not an
/// error. [`Err`] means the engine could not be asked or would not answer; see [`CapiVerifyError`].
///
/// With [`CapiOptions::default`] this is the run PITTv2's CAPI panel performed: this machine's trust,
/// revocation over the chain excluding the root, lower-quality chains reported, and the base policy
/// provider. Supplying [`CapiOptions::trust_anchors`] swaps the machine's trust for an exclusive
/// root store built from those anchors, which is how a controlled comparison against certval is set
/// up.
pub fn verify(
    target_der: &[u8],
    options: &CapiOptions,
) -> Result<CapiVerification, CapiVerifyError> {
    // Prepared before any handle is opened: an unrepresentable OID is a caller error, and finding
    // it after allocating a store and an engine would mean unwinding them for nothing.
    let usage_oids = c_strings(&options.requested_usage)?;
    let policy_oids = c_strings(&options.requested_issuance_policy)?;

    let target_ctx = CertContextGuard::create(target_der)?;

    // Both stores are built unconditionally-if-non-empty and held to the end of the function: the
    // engine and the chain builder keep referring to them for the whole call, so dropping either
    // early would pull material out from under a build in progress.
    let additional_store = if options.additional_certs.is_empty() {
        None
    } else {
        Some(memory_store(&options.additional_certs)?)
    };
    let root_store = if options.trust_anchors.is_empty() {
        None
    } else {
        Some(memory_store(&options.trust_anchors)?)
    };
    let engine = match &root_store {
        Some(store) => Some(EngineGuard::create(store.0)?),
        None => None,
    };

    // The OID pointer arrays borrow from the CString vectors above, so both must outlive the call.
    let mut usage_ptrs = pstrs(&usage_oids);
    let mut policy_ptrs = pstrs(&policy_oids);

    let mut para = CERT_CHAIN_PARA {
        cbSize: core::mem::size_of::<CERT_CHAIN_PARA>() as u32,
        ..Default::default()
    };
    if !usage_ptrs.is_empty() {
        para.RequestedUsage.dwType = usage_match(options.usage_match);
        para.RequestedUsage.Usage.cUsageIdentifier = usage_ptrs.len() as u32;
        para.RequestedUsage.Usage.rgpszUsageIdentifier = usage_ptrs.as_mut_ptr();
    }
    if !policy_ptrs.is_empty() {
        para.RequestedIssuancePolicy.dwType = usage_match(options.usage_match);
        para.RequestedIssuancePolicy.Usage.cUsageIdentifier = policy_ptrs.len() as u32;
        para.RequestedIssuancePolicy.Usage.rgpszUsageIdentifier = policy_ptrs.as_mut_ptr();
    }
    para.dwUrlRetrievalTimeout = options.url_retrieval_timeout_ms;

    let mut flags = revocation_flags(options.revocation);
    if options.return_lower_quality_chains {
        flags |= CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS;
    }

    // Held by value so the pointer handed to Win32 stays valid for the duration of the call.
    let toi = options.time_of_interest.map(unix_secs_to_filetime);
    let ptime = match &toi {
        Some(ft) => ptr::from_ref(ft),
        None => ptr::null(),
    };

    let mut chain_ctx: *mut CERT_CHAIN_CONTEXT = ptr::null_mut();
    // SAFETY: `target_ctx` is a live context from `CertCreateCertificateContext`; `ptime` is either
    // null or points at `toi`, which outlives the call; `para`'s OID arrays borrow from
    // `usage_oids`/`policy_oids`, which also outlive it; `chain_ctx` is a writable out-parameter.
    // The engine and stores, when present, are live for the whole scope.
    let built = unsafe {
        CertGetCertificateChain(
            engine.as_ref().map(|e| e.0),
            target_ctx.0,
            Some(ptime),
            additional_store.as_ref().map(|s| s.0),
            &para,
            flags,
            None,
            &mut chain_ctx,
        )
    };
    if let Err(e) = built {
        return Err(CapiVerifyError::ChainBuildFailed(hresult(&e)));
    }
    if chain_ctx.is_null() {
        // Documented as impossible when the call succeeds, but a null here would turn every
        // dereference below into undefined behavior, so it is checked rather than assumed.
        return Err(CapiVerifyError::ChainBuildFailed(0));
    }
    let chain_ctx = ChainGuard(chain_ctx);

    let policy_result = if options.build_only {
        None
    } else {
        Some(check_policy(chain_ctx.0, options)?)
    };

    // SAFETY: `chain_ctx.0` is non-null and owned by the guard, which is alive until this function
    // returns; every pointer read below is reachable from it and, per the module note, is copied
    // rather than retained.
    let (chains, context_status) = unsafe { collect_chains(chain_ctx.0, options) };

    let (policy_error, policy_error_location) = match policy_result {
        Some(Some((err, location))) => (Some(err), Some(location)),
        _ => (None, None),
    };

    // A build-only run is judged on the trust status the engine reported, since there is no policy
    // verdict to judge it on. PITTv2 scored such a run as invalid unconditionally, because its
    // `validated` flag was only ever set by the policy check it had just skipped.
    let validated = !chains.is_empty() && context_status.is_ok() && policy_error.is_none();

    Ok(CapiVerification {
        target: summarize(target_der),
        target_der: target_der.to_vec(),
        chains,
        trust_status: context_status,
        policy_error,
        policy_error_location,
        validated,
    })
}

/// What the policy check found: the code it reported and where it laid the blame, as
/// `(chain index, element index)`.
///
/// A pair rather than a struct because it is internal to this module -- it is unpacked into
/// [`CapiVerification::policy_error`] and
/// [`CapiVerification::policy_error_location`] a few lines after it is built.
type PolicyFinding = (CapiError, (i32, i32));

/// Runs the policy check, returning `Ok(None)` when it passed and `Ok(Some(..))` when it reported a
/// policy error.
///
/// The two failure modes are kept apart deliberately: the call itself failing is a
/// [`CapiVerifyError::PolicyCheckFailed`], while the call succeeding and reporting `dwError` is a
/// finding about the certificate. PITTv2 set the same error string for both.
fn check_policy(
    chain: *const CERT_CHAIN_CONTEXT,
    options: &CapiOptions,
) -> Result<Option<PolicyFinding>, CapiVerifyError> {
    let para = CERT_CHAIN_POLICY_PARA {
        cbSize: core::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
        dwFlags: if options.ignore_not_time_nested {
            CERT_CHAIN_POLICY_IGNORE_NOT_TIME_NESTED_FLAG
        } else {
            CERT_CHAIN_POLICY_FLAGS(0)
        },
        pvExtraPolicyPara: ptr::null_mut(),
    };
    let mut status = CERT_CHAIN_POLICY_STATUS {
        cbSize: core::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
        ..Default::default()
    };

    // SAFETY: `chain` is a live chain context; both structures are sized as Win32 requires and are
    // owned by this frame for the duration of the call.
    let ok = unsafe {
        CertVerifyCertificateChainPolicy(policy_oid(options.policy), chain, &para, &mut status)
    };
    if !ok.as_bool() {
        return Err(CapiVerifyError::PolicyCheckFailed(last_error()));
    }

    if status.dwError == 0 {
        Ok(None)
    } else {
        Ok(Some((
            CapiError(status.dwError),
            (status.lChainIndex, status.lElementIndex),
        )))
    }
}

/// Walks the preferred chain context and any lower-quality ones, copying everything out.
///
/// # Safety
///
/// `ctx` must be a live `CERT_CHAIN_CONTEXT` that outlives the call.
unsafe fn collect_chains(
    ctx: *const CERT_CHAIN_CONTEXT,
    options: &CapiOptions,
) -> (Vec<CapiChain>, CapiTrustStatus) {
    let mut chains = Vec::new();
    let context_status = CapiTrustStatus::new(
        (*ctx).TrustStatus.dwErrorStatus,
        (*ctx).TrustStatus.dwInfoStatus,
    );

    collect_simple_chains(ctx, false, &mut chains, options);

    // Only walked when they were asked for. The engine can return them regardless of the flag, and
    // reporting a chain the caller did not ask about would make the same target produce different
    // output depending on a setting that reads as "also show me more".
    if options.return_lower_quality_chains {
        let lower = (*ctx).cLowerQualityChainContext as usize;
        for i in 0..lower {
            let lq = *(*ctx).rgpLowerQualityChainContext.add(i);
            if lq.is_null() {
                continue;
            }
            collect_simple_chains(lq, true, &mut chains, options);
        }
    }

    (chains, context_status)
}

/// Copies every simple chain out of one chain context, appending to `out`.
///
/// # Safety
///
/// `ctx` must be a live `CERT_CHAIN_CONTEXT` that outlives the call.
unsafe fn collect_simple_chains(
    ctx: *const CERT_CHAIN_CONTEXT,
    lower_quality: bool,
    out: &mut Vec<CapiChain>,
    options: &CapiOptions,
) {
    for i in 0..(*ctx).cChain as usize {
        let simple = *(*ctx).rgpChain.add(i);
        if simple.is_null() {
            continue;
        }
        let mut elements = Vec::new();
        for j in 0..(*simple).cElement as usize {
            let element = *(*simple).rgpElement.add(j);
            if element.is_null() {
                continue;
            }
            elements.push(collect_element(element, options));
        }
        out.push(CapiChain {
            index: out.len(),
            lower_quality,
            trust_status: CapiTrustStatus::new(
                (*simple).TrustStatus.dwErrorStatus,
                (*simple).TrustStatus.dwInfoStatus,
            ),
            elements,
        });
    }
}

/// Copies one chain element out.
///
/// # Safety
///
/// `element` must be a live `CERT_CHAIN_ELEMENT` that outlives the call.
unsafe fn collect_element(
    element: *const CERT_CHAIN_ELEMENT,
    options: &CapiOptions,
) -> CapiElement {
    let der = context_der((*element).pCertContext);
    let extended_error_info = if (*element).pwszExtendedErrorInfo.is_null() {
        None
    } else {
        (*element).pwszExtendedErrorInfo.to_string().ok()
    };

    CapiElement {
        cert: summarize(&der),
        der,
        trust_status: CapiTrustStatus::new(
            (*element).TrustStatus.dwErrorStatus,
            (*element).TrustStatus.dwInfoStatus,
        ),
        revocation: collect_revocation((*element).pRevocationInfo, options),
        extended_error_info,
    }
}

/// Copies an element's revocation information out, when the engine recorded any.
///
/// # Safety
///
/// `info`, when non-null, must be a live `CERT_REVOCATION_INFO` that outlives the call.
unsafe fn collect_revocation(
    info: *const CERT_REVOCATION_INFO,
    options: &CapiOptions,
) -> Option<CapiRevocationInfo> {
    if info.is_null() {
        return None;
    }
    // A run that asked for no revocation checking still gets a zeroed structure on some Windows
    // versions; reporting "revocation check succeeded" from it would be a claim nothing made.
    if options.revocation == RevocationChecking::None {
        return None;
    }

    let oid = if (*info).pszRevocationOid.is_null() {
        None
    } else {
        (*info).pszRevocationOid.to_string().ok()
    };

    Some(CapiRevocationInfo {
        result: (*info).dwRevocationResult,
        oid,
        freshness_time: if (*info).fHasFreshnessTime.as_bool() {
            Some((*info).dwFreshnessTime)
        } else {
            None
        },
        crl: collect_crl_info((*info).pCrlInfo),
    })
}

/// Copies the CRL behind a revocation result out, when there was one.
///
/// # Safety
///
/// `info`, when non-null, must be a live `CERT_REVOCATION_CRL_INFO` that outlives the call.
unsafe fn collect_crl_info(info: *const CERT_REVOCATION_CRL_INFO) -> Option<CapiCrlInfo> {
    if info.is_null() {
        return None;
    }

    let (issuer, this_update, next_update) = crl_fields((*info).pBaseCrlContext);
    let (delta_issuer, delta_this_update, delta_next_update) = crl_fields((*info).pDeltaCrlContext);

    let entry = if (*info).pCrlEntry.is_null() {
        None
    } else {
        let e = (*info).pCrlEntry;
        // CAPI hands serial numbers back little-endian. PITTv2 reversed them at the point of
        // printing; reversing here means the value that reaches a report reads the same as the
        // serial on a certval row for the same certificate.
        let mut serial = core::slice::from_raw_parts(
            (*e).SerialNumber.pbData,
            (*e).SerialNumber.cbData as usize,
        )
        .to_vec();
        serial.reverse();
        Some(CapiCrlEntry {
            serial: buffer_to_hex(&serial),
            revocation_date: filetime_to_string(
                (*e).RevocationDate.dwLowDateTime,
                (*e).RevocationDate.dwHighDateTime,
            ),
        })
    };

    Some(CapiCrlInfo {
        issuer,
        this_update,
        next_update,
        entry,
        entry_from_delta: (*info).fDeltaCrlEntry.as_bool(),
        delta_issuer,
        delta_this_update,
        delta_next_update,
    })
}

/// Issuer, `thisUpdate` and `nextUpdate` of a CRL, by decoding the encoding CAPI handed back.
///
/// Decoded here rather than read from `CRL_CONTEXT::pCrlInfo` so the issuer is rendered by the same
/// `name_to_string` that renders every other name in a PITTv3 report. Reading the parsed structure
/// would mean calling `CertNameToStr`, whose output differs from certval's in separator and
/// attribute spelling — a difference that would show up in a comparison as though the two tools
/// disagreed about the CRL.
///
/// # Safety
///
/// `ctx`, when non-null, must be a live `CRL_CONTEXT` that outlives the call.
unsafe fn crl_fields(ctx: *const CRL_CONTEXT) -> (Option<String>, Option<String>, Option<String>) {
    if ctx.is_null() {
        return (None, None, None);
    }
    let encoded = core::slice::from_raw_parts((*ctx).pbCrlEncoded, (*ctx).cbCrlEncoded as usize);
    match CertificateList::<Rfc5280>::from_der(encoded) {
        Ok(crl) => {
            let tbs = &crl.tbs_cert_list;
            (
                Some(name_to_string(&tbs.issuer)),
                Some(tbs.this_update.to_string()),
                tbs.next_update.map(|t| t.to_string()),
            )
        }
        Err(e) => {
            // The engine used this CRL, so it parsed for CAPI. Saying so is worth more than a
            // silent `None`: it is the same kind of finding as a certificate CAPI accepts and
            // certval does not.
            warn!("CAPI supplied a CRL that would not decode here: {e}");
            (None, None, None)
        }
    }
}

/// A [`CertSummary`] for `der`, or `None` when certval will not parse it.
///
/// `None` is a reportable outcome rather than a failure — see [`CapiVerification::target`].
fn summarize(der: &[u8]) -> Option<CertSummary> {
    if der.is_empty() {
        return None;
    }
    match PDVCertificate::try_from(der) {
        Ok(cert) => Some(CertSummary::from_cert(&cert)),
        Err(e) => {
            debug!("CAPI accepted a certificate that would not decode here: {e}");
            None
        }
    }
}

/// The DER behind a `CERT_CONTEXT`, copied.
///
/// # Safety
///
/// `ctx`, when non-null, must be a live `CERT_CONTEXT` that outlives the call.
unsafe fn context_der(ctx: *const CERT_CONTEXT) -> Vec<u8> {
    if ctx.is_null() {
        return Vec::new();
    }
    core::slice::from_raw_parts((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize).to_vec()
}

fn usage_match(m: UsageMatch) -> u32 {
    match m {
        UsageMatch::Or => USAGE_MATCH_TYPE_OR,
        UsageMatch::And => USAGE_MATCH_TYPE_AND,
    }
}

fn revocation_flags(r: RevocationChecking) -> u32 {
    match r {
        RevocationChecking::None => 0,
        RevocationChecking::EndCertOnly => CERT_CHAIN_REVOCATION_CHECK_END_CERT,
        RevocationChecking::Chain => CERT_CHAIN_REVOCATION_CHECK_CHAIN,
        RevocationChecking::ChainExcludeRoot => CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
    }
}

fn policy_oid(p: ChainPolicy) -> PCSTR {
    match p {
        ChainPolicy::Base => CERT_CHAIN_POLICY_BASE,
        ChainPolicy::BasicConstraints => CERT_CHAIN_POLICY_BASIC_CONSTRAINTS,
        ChainPolicy::Authenticode => CERT_CHAIN_POLICY_AUTHENTICODE,
        ChainPolicy::Ssl => CERT_CHAIN_POLICY_SSL,
        ChainPolicy::NtAuth => CERT_CHAIN_POLICY_NT_AUTH,
        ChainPolicy::Ev => CERT_CHAIN_POLICY_EV,
    }
}

/// Win32 takes OIDs as C strings, so an interior NUL makes one unrepresentable. Reported as
/// [`CapiVerifyError::InvalidOid`] rather than silently truncated, which is what passing the prefix
/// would amount to: a different policy set than the caller asked for, validated without complaint.
fn c_strings(oids: &[String]) -> Result<Vec<CString>, CapiVerifyError> {
    oids.iter()
        .map(|o| CString::new(o.as_str()).map_err(|_| CapiVerifyError::InvalidOid(o.clone())))
        .collect()
}

/// Pointers into `oids`, as `CERT_USAGE_MATCH` wants them. The returned vector borrows, so both must
/// outlive the Win32 call that reads them.
fn pstrs(oids: &[CString]) -> Vec<PSTR> {
    oids.iter().map(|c| PSTR(c.as_ptr() as *mut u8)).collect()
}

fn unix_secs_to_filetime(secs: u64) -> FILETIME {
    // 11_644_473_600 is the offset from the Windows epoch; see `types::filetime_to_unix_secs`, whose
    // inverse this is and which is tested on every target.
    let ticks = (secs + 11_644_473_600) * 10_000_000;
    FILETIME {
        dwLowDateTime: (ticks & 0xFFFF_FFFF) as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    }
}

/// The `HRESULT` behind a `windows::core::Error`, as the `u32` the status tables are keyed on.
fn hresult(e: &windows::core::Error) -> u32 {
    e.code().0 as u32
}

/// `GetLastError` as an `HRESULT`, for the calls that report failure through a `BOOL`.
fn last_error() -> u32 {
    windows::core::Error::from_win32().code().0 as u32
}

/// Opens an in-memory certificate store holding `certs`.
///
/// In memory rather than on disk or in a system store: these are inputs to one run, and writing a
/// caller's trust anchors into the user's `ROOT` store to validate against them would be a side
/// effect nobody asked for and that outlives the process.
fn memory_store(certs: &[Vec<u8>]) -> Result<StoreGuard, CapiVerifyError> {
    // SAFETY: the memory provider takes no parameters; a null `pvPara` is what it expects.
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_MEMORY,
            CERT_QUERY_ENCODING_TYPE(0),
            None,
            CERT_OPEN_STORE_FLAGS(0),
            None,
        )
    }
    .map_err(|e| CapiVerifyError::StoreFailed(hresult(&e)))?;
    let guard = StoreGuard(store);

    for der in certs {
        if der.is_empty() {
            continue;
        }
        // SAFETY: `guard.0` is a live store handle; `der` is a live slice for the duration of the
        // call, and the store copies the encoding rather than retaining the pointer.
        unsafe {
            CertAddEncodedCertificateToStore(
                Some(guard.0),
                ENCODINGS,
                der,
                CERT_STORE_ADD_ALWAYS,
                None,
            )
        }
        .map_err(|e| CapiVerifyError::StoreFailed(hresult(&e)))?;
    }
    Ok(guard)
}

/// A `CERT_CONTEXT` owned by this crate, freed on drop.
struct CertContextGuard(*const CERT_CONTEXT);

impl CertContextGuard {
    fn create(der: &[u8]) -> Result<Self, CapiVerifyError> {
        // SAFETY: `der` is live for the duration of the call; the context copies the encoding.
        let ctx = unsafe { CertCreateCertificateContext(ENCODINGS, der) };
        if ctx.is_null() {
            return Err(CapiVerifyError::TargetNotParsed(last_error()));
        }
        Ok(CertContextGuard(ctx))
    }
}

impl Drop for CertContextGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `CertCreateCertificateContext` and is freed exactly once, here.
        unsafe {
            let _ = CertFreeCertificateContext(Some(self.0));
        }
    }
}

/// An `HCERTSTORE` owned by this crate, closed on drop.
struct StoreGuard(HCERTSTORE);

impl Drop for StoreGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `CertOpenStore` and is closed exactly once, here.
        unsafe {
            let _ = CertCloseStore(Some(self.0), 0);
        }
    }
}

/// An `HCERTCHAINENGINE` owned by this crate, freed on drop.
struct EngineGuard(HCERTCHAINENGINE);

impl EngineGuard {
    /// An engine whose *only* roots are those in `exclusive_root`.
    ///
    /// `hExclusiveRoot` rather than `hRestrictedRoot`: the restricted form narrows the machine's
    /// trust to a subset of what is already there, so an anchor the machine has never seen would be
    /// ignored — which would make a comparison against certval silently test a different anchor set
    /// than the one supplied. The exclusive form replaces the trust set outright.
    fn create(exclusive_root: HCERTSTORE) -> Result<Self, CapiVerifyError> {
        let config = CERT_CHAIN_ENGINE_CONFIG {
            cbSize: core::mem::size_of::<CERT_CHAIN_ENGINE_CONFIG>() as u32,
            // Matches PITTv2's engine configuration.
            dwFlags: CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_ENABLE_CACHE_AUTO_UPDATE,
            hExclusiveRoot: exclusive_root,
            ..Default::default()
        };
        let mut engine = HCERTCHAINENGINE::default();
        // SAFETY: `config` is sized as Win32 requires and lives for the call; `engine` is a
        // writable out-parameter. The store must outlive the engine, which the caller arranges by
        // holding both to the end of `verify`.
        unsafe { CertCreateCertificateChainEngine(&config, &mut engine) }
            .map_err(|e| CapiVerifyError::EngineFailed(hresult(&e)))?;
        Ok(EngineGuard(engine))
    }
}

impl Drop for EngineGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `CertCreateCertificateChainEngine` and is freed exactly once.
        unsafe { CertFreeCertificateChainEngine(Some(self.0)) }
    }
}

/// A `CERT_CHAIN_CONTEXT` owned by this crate, freed on drop.
///
/// This is the guard PITTv2 did without — see the module documentation.
struct ChainGuard(*const CERT_CHAIN_CONTEXT);

impl Drop for ChainGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` is non-null (checked at construction), came from
        // `CertGetCertificateChain` and is freed exactly once, here. Everything reachable from it
        // has already been copied out.
        unsafe { CertFreeCertificateChain(self.0) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{ERROR_FLAGS, INFO_FLAGS};
    use std::fs;
    use std::path::Path;

    /// The instant the PKITS material is valid at, as `pittv3-gui-lib`'s tests use it.
    const TOI: u64 = 1_648_039_783;

    fn pkits(name: &str) -> Vec<u8> {
        let p = Path::new("../certval/tests/examples/PKITS_data_p256/certs").join(name);
        fs::read(&p).unwrap_or_else(|e| panic!("failed to read {}: {e}", p.display()))
    }

    /// Every flag value in the portable tables is the one the `windows` crate defines.
    ///
    /// This is why the tables can be hand-written constants in a module that builds everywhere: a
    /// transcription slip fails here rather than mislabeling a verdict in a report, where nobody
    /// would have a second source to check it against.
    #[test]
    fn portable_flag_tables_match_the_windows_crate() {
        let expected_errors: &[(u32, &str)] = &[
            (CERT_TRUST_IS_NOT_TIME_VALID, "CERT_TRUST_IS_NOT_TIME_VALID"),
            (
                CERT_TRUST_IS_NOT_TIME_NESTED,
                "CERT_TRUST_IS_NOT_TIME_NESTED",
            ),
            (CERT_TRUST_IS_REVOKED, "CERT_TRUST_IS_REVOKED"),
            (
                CERT_TRUST_IS_NOT_SIGNATURE_VALID,
                "CERT_TRUST_IS_NOT_SIGNATURE_VALID",
            ),
            (
                CERT_TRUST_IS_NOT_VALID_FOR_USAGE,
                "CERT_TRUST_IS_NOT_VALID_FOR_USAGE",
            ),
            (CERT_TRUST_IS_UNTRUSTED_ROOT, "CERT_TRUST_IS_UNTRUSTED_ROOT"),
            (
                CERT_TRUST_REVOCATION_STATUS_UNKNOWN,
                "CERT_TRUST_REVOCATION_STATUS_UNKNOWN",
            ),
            (CERT_TRUST_IS_CYCLIC, "CERT_TRUST_IS_CYCLIC"),
            (CERT_TRUST_INVALID_EXTENSION, "CERT_TRUST_INVALID_EXTENSION"),
            (
                CERT_TRUST_INVALID_POLICY_CONSTRAINTS,
                "CERT_TRUST_INVALID_POLICY_CONSTRAINTS",
            ),
            (
                CERT_TRUST_INVALID_BASIC_CONSTRAINTS,
                "CERT_TRUST_INVALID_BASIC_CONSTRAINTS",
            ),
            (
                CERT_TRUST_INVALID_NAME_CONSTRAINTS,
                "CERT_TRUST_INVALID_NAME_CONSTRAINTS",
            ),
            (
                CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT,
                "CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT",
            ),
            (
                CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT,
                "CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT",
            ),
            (
                CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT,
                "CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT",
            ),
            (
                CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT,
                "CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT",
            ),
            (CERT_TRUST_IS_PARTIAL_CHAIN, "CERT_TRUST_IS_PARTIAL_CHAIN"),
            (
                CERT_TRUST_CTL_IS_NOT_TIME_VALID,
                "CERT_TRUST_CTL_IS_NOT_TIME_VALID",
            ),
            (
                CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID,
                "CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID",
            ),
            (
                CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE,
                "CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE",
            ),
            (
                CERT_TRUST_HAS_WEAK_SIGNATURE,
                "CERT_TRUST_HAS_WEAK_SIGNATURE",
            ),
            (
                CERT_TRUST_IS_OFFLINE_REVOCATION,
                "CERT_TRUST_IS_OFFLINE_REVOCATION",
            ),
            (
                CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY,
                "CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY",
            ),
            (
                CERT_TRUST_IS_EXPLICIT_DISTRUST,
                "CERT_TRUST_IS_EXPLICIT_DISTRUST",
            ),
            (
                CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT,
                "CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT",
            ),
        ];
        assert_eq!(ERROR_FLAGS, expected_errors);

        let expected_info: &[(u32, &str)] = &[
            (
                CERT_TRUST_HAS_EXACT_MATCH_ISSUER,
                "CERT_TRUST_HAS_EXACT_MATCH_ISSUER",
            ),
            (
                CERT_TRUST_HAS_KEY_MATCH_ISSUER,
                "CERT_TRUST_HAS_KEY_MATCH_ISSUER",
            ),
            (
                CERT_TRUST_HAS_NAME_MATCH_ISSUER,
                "CERT_TRUST_HAS_NAME_MATCH_ISSUER",
            ),
            (CERT_TRUST_IS_SELF_SIGNED, "CERT_TRUST_IS_SELF_SIGNED"),
            (
                CERT_TRUST_AUTO_UPDATE_CA_REVOCATION,
                "CERT_TRUST_AUTO_UPDATE_CA_REVOCATION",
            ),
            (
                CERT_TRUST_AUTO_UPDATE_END_REVOCATION,
                "CERT_TRUST_AUTO_UPDATE_END_REVOCATION",
            ),
            (
                CERT_TRUST_NO_OCSP_FAILOVER_TO_CRL,
                "CERT_TRUST_NO_OCSP_FAILOVER_TO_CRL",
            ),
            (CERT_TRUST_IS_KEY_ROLLOVER, "CERT_TRUST_IS_KEY_ROLLOVER"),
            (
                CERT_TRUST_HAS_PREFERRED_ISSUER,
                "CERT_TRUST_HAS_PREFERRED_ISSUER",
            ),
            (
                CERT_TRUST_HAS_ISSUANCE_CHAIN_POLICY,
                "CERT_TRUST_HAS_ISSUANCE_CHAIN_POLICY",
            ),
            (
                CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS,
                "CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS",
            ),
            (CERT_TRUST_IS_PEER_TRUSTED, "CERT_TRUST_IS_PEER_TRUSTED"),
            (
                CERT_TRUST_HAS_CRL_VALIDITY_EXTENDED,
                "CERT_TRUST_HAS_CRL_VALIDITY_EXTENDED",
            ),
            (
                CERT_TRUST_IS_FROM_EXCLUSIVE_TRUST_STORE,
                "CERT_TRUST_IS_FROM_EXCLUSIVE_TRUST_STORE",
            ),
            (CERT_TRUST_IS_CA_TRUSTED, "CERT_TRUST_IS_CA_TRUSTED"),
            (
                CERT_TRUST_HAS_AUTO_UPDATE_WEAK_SIGNATURE,
                "CERT_TRUST_HAS_AUTO_UPDATE_WEAK_SIGNATURE",
            ),
            (CERT_TRUST_IS_COMPLEX_CHAIN, "CERT_TRUST_IS_COMPLEX_CHAIN"),
            (
                CERT_TRUST_HAS_ALLOW_WEAK_SIGNATURE,
                "CERT_TRUST_HAS_ALLOW_WEAK_SIGNATURE",
            ),
            (
                CERT_TRUST_SSL_HANDSHAKE_OCSP,
                "CERT_TRUST_SSL_HANDSHAKE_OCSP",
            ),
            (
                CERT_TRUST_SSL_TIME_VALID_OCSP,
                "CERT_TRUST_SSL_TIME_VALID_OCSP",
            ),
            (
                CERT_TRUST_SSL_RECONNECT_OCSP,
                "CERT_TRUST_SSL_RECONNECT_OCSP",
            ),
            (CERT_TRUST_SSL_TIME_VALID, "CERT_TRUST_SSL_TIME_VALID"),
        ];
        assert_eq!(INFO_FLAGS, expected_info);
    }

    /// The `FILETIME` written for a time of interest round-trips through the portable conversion,
    /// so the two halves of the boundary cannot drift apart.
    #[test]
    fn time_of_interest_round_trips() {
        let ft = unix_secs_to_filetime(TOI);
        assert_eq!(
            crate::types::filetime_to_unix_secs(ft.dwLowDateTime, ft.dwHighDateTime),
            Some(TOI as i64)
        );
    }

    /// Bytes CAPI will not parse are an error naming that, not a panic and not a false verdict.
    #[test]
    fn garbage_is_rejected_by_capi_not_misreported() {
        let err = verify(&[0u8; 32], &CapiOptions::default()).unwrap_err();
        assert!(
            matches!(err, CapiVerifyError::TargetNotParsed(_)),
            "expected TargetNotParsed, got {err:?}"
        );
    }

    /// An empty input is rejected the same way, rather than reaching the chain builder.
    #[test]
    fn empty_input_is_rejected() {
        let err = verify(&[], &CapiOptions::default()).unwrap_err();
        assert!(matches!(err, CapiVerifyError::TargetNotParsed(_)));
    }

    /// A PKITS end entity, validated against the PKITS root supplied as an exclusive trust anchor
    /// with the intermediate offered as an additional certificate: the whole point of the crate,
    /// end to end, and the case the eventual button runs.
    ///
    /// Revocation is off because the PKITS material has no revocation source reachable from this
    /// machine, and leaving it on would make the assertion depend on the network.
    #[test]
    fn pkits_path_validates_against_supplied_anchors() {
        let options = CapiOptions {
            revocation: RevocationChecking::None,
            time_of_interest: Some(TOI),
            trust_anchors: vec![pkits("TrustAnchorRootCertificate.crt")],
            additional_certs: vec![pkits("GoodCACert.crt")],
            ..Default::default()
        };
        let result = verify(&pkits("ValidCertificatePathTest1EE.crt"), &options).unwrap();

        assert!(
            result.validated,
            "expected a valid path; context status: {}, policy: {:?}",
            result.trust_status.describe(),
            result.policy_error.map(|e| e.describe())
        );

        let chain = result.chains.first().expect("a chain was built");
        assert_eq!(
            chain.elements.len(),
            3,
            "expected target, intermediate and root"
        );
        // CAPI orders a chain from the target outward, which is the reverse of certval's ordering.
        let target = chain.elements[0].cert.as_ref().expect("target parsed");
        let root = chain.elements[2].cert.as_ref().expect("root parsed");
        assert!(target.subject.contains("Valid EE Certificate Test1"));
        assert!(root.subject.contains("Trust Anchor"));
        // The root is self-signed and came from the exclusive store, both of which the engine says
        // in the information bits rather than the error bits.
        assert!(chain.elements[2]
            .trust_status
            .has_info(CERT_TRUST_IS_SELF_SIGNED));
    }

    /// The same target with no anchors supplied, so the engine judges it by this machine's stores.
    ///
    /// No verdict is asserted: it depends on what those stores hold, and they vary from machine to
    /// machine on purpose. What does not vary is that the run comes back as a verdict rather than
    /// an error, with a chain that starts at the target -- the shape of a real "Validate Using CAPI"
    /// run with the checkbox off, whichever way the verdict goes.
    #[test]
    fn pkits_target_gets_a_verdict_against_machine_stores() {
        let options = CapiOptions {
            revocation: RevocationChecking::None,
            time_of_interest: Some(TOI),
            additional_certs: vec![
                pkits("GoodCACert.crt"),
                pkits("TrustAnchorRootCertificate.crt"),
            ],
            ..Default::default()
        };
        let target = pkits("ValidCertificatePathTest1EE.crt");
        let result = verify(&target, &options).unwrap();

        let chain = result.chains.first().expect("a chain was built");
        assert_eq!(
            chain.elements[0].der, target,
            "the chain starts at the target"
        );
        assert!(result.target.is_some(), "the target parsed here as well");
    }

    /// A build-only run reports the engine's own verdict and no policy error. PITTv2 scored every
    /// build-only run as invalid because its `validated` flag was only set by the policy check it
    /// had just skipped; this is the behavior that replaces that.
    #[test]
    fn build_only_still_yields_a_verdict() {
        let options = CapiOptions {
            build_only: true,
            revocation: RevocationChecking::None,
            time_of_interest: Some(TOI),
            trust_anchors: vec![pkits("TrustAnchorRootCertificate.crt")],
            additional_certs: vec![pkits("GoodCACert.crt")],
            ..Default::default()
        };
        let result = verify(&pkits("ValidCertificatePathTest1EE.crt"), &options).unwrap();

        assert!(result.policy_error.is_none());
        assert!(result.policy_error_location.is_none());
        assert!(
            result.validated,
            "a clean build-only run is a pass: {}",
            result.trust_status.describe()
        );
    }

    /// An OID with an interior NUL cannot reach Win32 and is named rather than truncated, which
    /// would otherwise validate against a different policy set than the caller asked for.
    #[test]
    fn interior_nul_in_an_oid_is_an_error() {
        let options = CapiOptions {
            requested_issuance_policy: vec!["2.16.840.1.101.3.2.1.48.1\0extra".into()],
            ..Default::default()
        };
        let err = verify(&pkits("ValidCertificatePathTest1EE.crt"), &options).unwrap_err();
        assert!(matches!(err, CapiVerifyError::InvalidOid(_)), "{err:?}");
    }

    /// Asking for no lower-quality contexts reports no lower-quality chains, whatever the engine
    /// chose to return.
    #[test]
    fn lower_quality_chains_are_only_reported_when_asked_for() {
        let options = CapiOptions {
            return_lower_quality_chains: false,
            revocation: RevocationChecking::None,
            time_of_interest: Some(TOI),
            trust_anchors: vec![pkits("TrustAnchorRootCertificate.crt")],
            additional_certs: vec![pkits("GoodCACert.crt")],
            ..Default::default()
        };
        let result = verify(&pkits("ValidCertificatePathTest1EE.crt"), &options).unwrap();
        assert!(result.chains.iter().all(|c| !c.lower_quality));
    }

    /// Every element carries its encoding whether or not certval parsed it, and the digest in the
    /// summary is over exactly those bytes — which is what lets a CAPI row and a certval row be
    /// matched up as the same certificate.
    #[test]
    fn elements_carry_their_encoding_and_a_matching_digest() {
        let options = CapiOptions {
            revocation: RevocationChecking::None,
            time_of_interest: Some(TOI),
            trust_anchors: vec![pkits("TrustAnchorRootCertificate.crt")],
            additional_certs: vec![pkits("GoodCACert.crt")],
            ..Default::default()
        };
        let target = pkits("ValidCertificatePathTest1EE.crt");
        let result = verify(&target, &options).unwrap();
        let chain = result.chains.first().unwrap();

        assert_eq!(chain.elements[0].der, target);
        assert_eq!(
            chain.elements[0].cert.as_ref().unwrap().sha256,
            Some(pittv3_lib::report::sha256_hex(&target))
        );
        for element in &chain.elements {
            assert!(!element.der.is_empty());
        }
    }
}
