//! Structures and functions to perform CRL processing client functionality (minus support for delta CRLs,
//! indirect CRLs, on hold, and nameRelativeToIssuer distribution points)

extern crate alloc;
use alloc::{format, string::String, vec::Vec};
use flagset::{flags, FlagSet};
use lazy_static::lazy_static;
use ndarray::{arr2, ArrayBase, Dim, OwnedRepr};

use log::{error, info};

use const_oid::db::rfc5912::{
    ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS, ID_CE_CERTIFICATE_ISSUER,
    ID_CE_CRL_DISTRIBUTION_POINTS, ID_CE_CRL_NUMBER, ID_CE_CRL_REASONS, ID_CE_DELTA_CRL_INDICATOR,
    ID_CE_FRESHEST_CRL, ID_CE_HOLD_INSTRUCTION_CODE, ID_CE_INVALIDITY_DATE,
    ID_CE_ISSUING_DISTRIBUTION_POINT, ID_CE_KEY_USAGE,
};
use der::{Decode, Encode};
use x509_cert::ext::pkix::crl::dp::ReasonFlags;
use x509_cert::ext::pkix::{
    crl::dp::DistributionPoint,
    name::{DistributionPointName, GeneralName, GeneralNames},
    KeyUsages,
};
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, CrlDistributionPoints, IssuingDistributionPoint, KeyUsage,
};
use x509_cert::name::Name;
use x509_cert::{
    crl::{CertificateList, RevokedCert},
    ext::Extensions,
    Certificate,
};

use crate::crl::CrlReasons::AllReasons;
use crate::Error::CrlIncompatible;
use crate::{
    add_crl_entry, compare_names, get_time_of_interest, log_error_for_subject, name_to_string,
    set_validation_status, CertificationPathResults, CertificationPathSettings, DeferDecodeSigned,
    Error, ExtensionProcessing, PDVCertificate, PDVExtension, PathValidationStatus, PkiEnvironment,
    Result,
};

#[cfg(feature = "revocation")]
use crate::add_failed_crl;

#[cfg(feature = "remote")]
use std::time::Duration;

#[cfg(feature = "remote")]
use log::debug;

#[cfg(feature = "remote")]
use der::asn1::Ia5String;

#[cfg(feature = "remote")]
use alloc::vec;

#[cfg(feature = "remote")]
use crate::{add_crl, get_crl_timeout};

// Certificates are classified based on the values found in the CRLDistributionPoints and BasicConstraints
// extensions, if present, without regard for criticality.  Certificates with BasicConstraints present and
// the isCA field set to true are CA certificates.  Certificates without BasicConstraints or with BasicConstraints
// present and the isCA field set to false are EE certificates.  For either, if the CRLDistributionsPoints
// extension is present, the certificates gets a DP classification.
//
// enum CertRevType { EeDp, Ee, CaDp, Ca, Unsupported }
// - End-entity certificate with CRL DP 	(EeDp)
// - End-entity certificate with no CRL DP	(Ee)
// - CA certificate with CRL DP 			(CaDp)
// - CA certificate with no CRL DP			(Ca)

// CRLs are classified based on the values found in the IssuingDistributionPoint and DeltaCRLIndicator
// extensions, if present, without regard for criticality.  IssuingDistributionPoint is defined as follows
// (with related enumerations given as a ASN.1 comments for each field):
//
//	IssuingDistPointSyntax ::= SEQUENCE
//	{
//		distributionPoint			[0] DistributionPointName	OPTIONAL,		-- CrlScope
//		onlyContainsUserCerts		[1] BOOLEAN					DEFAULT FALSE,	-- CrlCoverage
//		onlyContainsAuthorityCerts	[2] BOOLEAN					DEFAULT FALSE,	-- CrlCoverage
//		onlySomeReasons				[3] ReasonFlags				OPTIONAL,		-- CrlReasons
//		indirectCRL					[4] BOOLEAN					DEFAULT FALSE,	-- CrlAuthority
//		onlyContainsAttributeCerts	[5] BOOLEAN					DEFAULT FALSE	-- CrlCoverage
//	}
//
//The DeltaCRLIndicator extension is simply an integer as defined below:
//
//	BaseCRLNumber ::= CRLNumber
//

// The CrlScope enum indicates the scope of the CRL, i.e. complete, delta or distribution point (further scoped by
// reason or other factors).  The value is determined by inspection of the DeltaCRLIndicator and/or the distributionPoint
// field of the IssuingDistributionPoint extension of the CRL.
//
// enum CrlScope {Complete, Dp, Delta, DeltaDp, Unsupported}
//	- Complete		: The CRL contains no DeltaCRLIndicator indicator and either has no IssuingDistributionPoint
//					  extension or has an IssuingDistributionPoint extension with no distributionPoint field.
//	- Dp			: The CRL contains no DeltaCRLIndicator indicator and has an IssuingDistributionPoint extension
//					  with a distributionPoint field.
//	- Delta		    : The CRL contains a DeltaCRLIndicator indicator and either has no IssuingDistributionPoint
//					  extension or has an IssuingDistributionPoint extension with no distributionPoint field.
//	- DeltaDp		: The CRL contains a DeltaCRLIndicator indicator and has an IssuingDistributionPoint extension
//					  with a distributionPoint field.

// The CrlCoverage enum indicates the type(s) of entities covered by the CRL.  The value is determined by inspection
// of the onlyContainsUserCerts, onlyContainsAuthorityCerts and onlyContainsAttributeCerts fields of the
// IssuingDistributionPoint extension in the CRL.  CRLs that contain more than one onlyContainsXXX field can be
// considered invalid and discarded.  (The fields are logically a CHOICE and should've been defined as such.)
//
// enum CrlCoverage {All, EeOnly, CaOnly, Unsupported}
//	- All			: The CRL contains no IssuingDistributionPoint extension or has an IssuingDistributionPoint
//					  extension with no onlyContainsUserCerts, onlyContainsAuthorityCerts or onlyContainsAttributeCerts
//					  fields set to true.
//	- EeOnly		: The CRL contains an IssuingDistributionPoint extension with onlyContainsUserCerts set to true.
//	- CaOnly		: The CRL contains an IssuingDistributionPoint extension with onlyContainsAuthorityCerts set to true.
//	- Unsupported	: Unsupported - the CRL contains an IssuingDistributionPoint extension with onlyContainsAttributeCerts set to true.

// The CrlCoverage value may also be used to determines the attributes to search when retrieving CRLs from a directory.
// Below are the relationship between each enumerated value and directory attributes (however, this implementation does
// not support LDAP so directory retrieval is moot in this context):
//	All		: certificateRevocationList, authorityRevocationList
//	EeOnly	: certificateRevocationList
//	CaOnly	: authorityRevocationList

// The CrlAuthority enum indicates whether or not the CRL includes revocation notifications for CAs other than the issuer
// of the CRL.  The value is determined by inspection of the indirectCRL field of the IssuingDistributionPoint extension
// of the CRL.
//
// enum CrlAuthority {Direct, Indirect, Unsupported}
//	- Direct	: The CRL contains no IssuingDistributionPoint extension or has an IssuingDistributionPoint
//				  extension with no indirectCRL field.
//	- Indirect	: The CRL contains an IssuingDistributionPoint extension with indirectCRL present.

// The CrlReasons enum indicates whether or not the CRL covers all reason codes or a subset.  The value is determined by
// inspection of the onlySomeReasons field of the IssuingDistributionPoint extension of the CRL.
//
// enum CrlReasons {AllReasons, SomeReasons, Unsupported}
//  - AllReasons	: The CRL contains no IssuingDistributionPoint extension or has an IssuingDistributionPoint
//				      extension with no onlySomeReasons field.
//  - SomeReasons : The CRL contains an IssuingDistributionPoint extension with onlySomeReasons present.

//Annex B of X.509 defines the following types of CRLs (given below along with CrlCoverage, CrlScope
//and CrlAuthority values that define the type)
//
//-	Full and complete CRL,				(All,	 Complete,	Direct)
//					  EPRL,				(EeOnly, Complete,	Direct)
//					  or CARL;			(CaOnly, Complete,	Direct)

//-	Indirect CRL,						(All,	 Complete,	Indirect)
//			 EPRL						(EeOnly, Complete,	Indirect)
//			 or CARL (ICRL);			(CaOnly, Complete,	Indirect)

//-	Delta CRL (dCRL),					(All,	 Delta,		Direct)
//		  dEPRL							(EeOnly, Delta,		Direct)
//		  or dCARL;						(CaOnly, Delta,		Direct)

//-	Indirect dCRL,						(All,	 Delta,		Indirect)
//			 dEPRL						(EeOnly, Delta,		Indirect)
//			 or dCARL.					(CaOnly, Delta,		Indirect)

//-	Distribution Point CRL,				(All,	 Dp,    	Direct)
//					   EPRL				(EeOnly, Dp,		Direct)
//					   or CARL;			(CaOnly, Dp,		Direct)

// Annex B of X.509 does not identify Indirect Distribution Point CRLs, Delta Distribution Point CRLs
// or Indirect Delta Distribution Point CRLs
// -	Indirect Distribution Point CRL,    (All,	 Dp,    	Indirect)
//								EPRL	    (EeOnly, Dp,		Indirect)
//								or CARL     (CaOnly, Dp,		Indirect)

// -	Delta Distribution Point CRL,	    (All,	 DeltaDp,	Direct)
//		  EPRL							    (EeOnly, DeltaDp,	Direct)
//		  or CARL						    (CaOnly, DeltaDp,	Direct)

// -	Indirect Delta Distrib. Point CRL,	(All,	 DeltaDp,	Indirect)
//			 EPRL						    (EeOnly, DeltaDp,	Indirect)
//			 or CARL.					    (CaOnly, DeltaDp,	Indirect)

// For each of the 24 types of CRLs identified above there are 2 possible varieties: CrAllReasons, CrSomeReasons.
// There are 48 types of CRLs in total.

// The CRL types that are permissible for each type of certificate are given below.
// CrlReasons are not considered as either value is always permissible from a validation point of view
// and depend on the reason codes of interest indicated by an application.  CrlAuthority is not considered
// as either value is always permissible.  The total number of permissible CRLs for each cert type is
// always the number identified below multiplied by four.

// End-entity certificate with CRL DP or freshestCRL (EeDp)
// PERMISSIBLE TYPES (8)
//	- CrlScope		: Complete, Dp, Delta, DeltaDp
//	- CrlCoverage	: All, EeOnly

//End-entity certificate with no CRL DP nor freshestCRL	(CtEe)
//PERMISSIBLE TYPES (4)
//	- CrlScope		: Complete, Delta
//	- CrlCoverage	: All, EeOnly

//CA certificate with CRL DP or freshestCRL (CaDp)
//PERMISSIBLE TYPES (8)
//	- CrlScope		: Complete, Dp, Delta, DeltaDp
//	- CrlCoverage	: All, CaOnly

//CA certificate with no CRL DP nor freshestCRL (CtCa)
//PERMISSIBLE TYPES (4)
//	- CrlScope		: Complete, Delta
//	- CrlCoverage	: All, CaOnly

lazy_static! {
    // Certificate types are rows, CRL scopes are columns.
    // enum CertRevType { CtEeDp, CtEe, CtCaDp, CtCa, CtUnsupported }
    // enum CrlScope { CsComplete, CsDp, CsDelta, CsDeltaDp, CsUnsupported}
    static ref COMPATIBLE_SCOPE : ArrayBase<OwnedRepr<bool>, Dim<[usize; 2]>> = arr2(&[
        // CsComplete,  CsDp, CsDelta, CsDeltaDp
        [        true,  true,    true,     true], // CtEeDp
        [        true, false,    true,    false], // CtEe
        [        true,  true,    true,     true], // CtCaDp
        [        true, false,    true,    false]  // CtCa
    ]);

    // Certificate types are rows, CRL coverages are columns.
    // enum CertRevType { CtEeDp, CtEe, CtCaDp, CtCa, CtUnsupported }
    // enum CrlCoverage {CcAll, CcEeOnly, CcCaOnly, CcUnsupported}
    static ref COMPATIBLE_COVERAGE : ArrayBase<OwnedRepr<bool>, Dim<[usize; 2]>> = arr2(&[
        //CcAll, CcEeOnly, CcCaOnly
        [  true,     true,  false], // CtEeDp
        [  true,     true,  false], // CtEe
        [  true,    false,   true], // CtCaDp
        [  true,    false,   true]  // CtCa
    ]);
}

/// The CertRevType enum is used to identify certificate with regard to types of CRLs that are applicable.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CertRevType {
    /// Certificate features a distribution point name and either no basicConstraints or basicConstraints with isCA set to false
    EeDp,
    /// Certificate features no distribution point name and either no basicConstraints or basicConstraints with isCA set to false
    Ee,
    /// Certificate features a distribution point name and basicConstraints with isCA set to true
    CaDp,
    /// Certificate features no distribution point name and basicConstraints with isCA set to true
    Ca,
}

/// The CrlScope enum is used to identify CRL scope, i.e., whether the CRL is full, partitioned, delta or
/// delta partianed. Partitioning is performed using issuing distribution point extensions.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CrlScope {
    /// CRL is not limited in scope by issuing distribution point or delta CRL indicator
    Complete,
    /// CRL is limited in scope by issuing distribution point but not by delta CRL indicator
    Dp,
    /// CRL is not limited in scope by issuing distribution point but includes a delta CRL indicator
    Delta,
    /// CRL is limited in scope by issuing distribution point and delta CRL indicator
    DeltaDp,
}

/// The CrlCoverage enum is used to identify CRL coverage, i.e., whether the CRL features entries for
/// all types of entities, only for CA entities or only for end entities.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CrlCoverage {
    /// CRL coverage is not limited by flags in issuing distribution point
    All,
    /// CRL coverage is limited to end entity certificates only by issuing distribution point
    EeOnly,
    /// CRL coverage is limited to CA certificates only by issuing distribution point
    CaOnly,
}

/// The CrlAuthority enum is used to identify CRL authority, i.e., whether a CRL is direct or indirect.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CrlAuthority {
    /// CRL only features entries that were issued by the CRL issuer
    Direct,
    /// CRL may feature entries that were issued by other than the CRL issuer
    Indirect,
}

/// The CrlReasons enum is used to identify CRL reasons.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CrlReasons {
    /// The CRL covers all CRL reasons
    AllReasons,
    /// The CRL covers only some CRL reasons
    SomeReasons,
}

/// CrlType features a set of enum values that determine the type of CRL based on evaluation of extensions.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CrlType {
    /// Indicates scope of CRL relative to distribution point and delta CRL indicator
    pub scope: CrlScope,
    /// Indicates if CRL is limited by IDP flags, i.e., end entity only, CA only
    pub coverage: CrlCoverage,
    /// Indicates if CRL only contains entries for certs issued by the CRL issuer or may contain entries from other issuers too
    pub authority: CrlAuthority,
    /// Indicates if CRL covers all CRL reasons or only some
    pub reasons: CrlReasons,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CrlInfo {
    pub type_info: CrlType,
    pub this_update: u64,
    pub next_update: Option<u64>,
    pub issuer_name: String,
    pub issuer_name_blob: Vec<u8>,
    pub sig_alg_blob: Vec<u8>,
    pub exts_blob: Option<Vec<u8>>,
    pub idp_name: Option<String>,
    pub idp_blob: Option<Vec<u8>>,
    pub skid: Option<Vec<u8>>,
    pub filename: Option<String>,
}

//CRL Processing Steps
//
//1)	Classify the target certificate as one of the 4 types of certificate
//2)	Determine the CRLs to obtain
//		a.	Identify the CRL types that apply (i.e. consult a static table w/ permissible CRLCOVERAGE and
//			CRLSCOPE values for each cert type)
//		b.	Identify locations from which to retrieve CRLs (i.e. certificate issuer directory entry vs.
//			CRLDP/freshestCRL)
//3)	Obtain CRL(s) - fail if no CRLs can be obtained
//4)	For each CRL, determine CRL and cert compatibility
//		a.	Confirm that the CRL type and cert type are compatible (discard CRL upon failure)
//		b.	Validate CRL issuer name (discard CRL upon failure)
//			i.	One of the names in a CRL DP crlIssuer field or the cert issuer shall match the CRL issuer.
//				If a CRL DP produced the match, set the active CRLDP state variable to the CRL DP containing
//				matching crlIssuer field.
//		c.	Validate DP (discard CRL upon failure)
//			i.	If the active CRL DP is set and an IDP w/distribution point field is present in the CRL, one
//				of the names in the active CRL DP shall match one of the names in the IDP DP.  If the active
//				CRL DP is not set and an IDP w/distribution point field is present, one of the names in a CRL
//				DP shall match one of the names in the IDP DP and the active CRL DP should be set to the CRL
//				DP that matches the IDP.
//			ii.	If reasons field is present in the active CRL DP, the onlySomeReasons field of the IDP shall
//				be absent or contain at least one of the reason codes asserted in the CRL DP
//		d.	Validate CRL authority (discard CRL upon failure)
//			i.	If the CRL issuer name does not match the cert issuer name, the indirectCRL field must be
//				present in the IDP.
//5)	For each CRL, determine CRL validity
//		a.	Currency check (discard CRL upon failure)
//		b.	Signature check (discard CRL upon failure)
//		c.	Validate delta scope (upon failure discard the CRL or set it aside pending acquisition of
//			additional CRLs)
//		d.	Process remaining CRL extensions
//6)	Determine if all necessary CRLs were obtained
//		a.	Process critical CRL DP and/or freshestCRL extensions (if requirements are not met try to obtain
//			additional CRLs or fail)
//		b.	Process reason codes of interest (If requirements are not met try to obtain additional CRLs or fail)
//		c.	Discard extraneous CRLs (optional)
//7)	For each CRL, review revocation notifications
//		a.	Check certificate status
//			i.	If certificate is found on a CRL, process any CRL entry extensions

/// get_crl_dps returns a list of URIs read from the CRL DP extension, if any.
#[cfg(feature = "remote")]
fn get_crl_dps(target_cert: &PDVCertificate) -> Vec<&Ia5String> {
    let mut retval = vec![];
    if let Ok(Some(PDVExtension::CrlDistributionPoints(crl_dps))) =
        target_cert.get_extension(&ID_CE_CRL_DISTRIBUTION_POINTS)
    {
        for crl_dp in &crl_dps.0 {
            if let Some(DistributionPointName::FullName(gns)) = &crl_dp.distribution_point {
                for gn in gns {
                    if let GeneralName::UniformResourceIdentifier(uri) = &gn {
                        if !retval.contains(&uri) {
                            retval.push(uri);
                        }
                    }
                }
            }
        }
    }
    retval
}

/// fetch_crl takes a string that notionally contains a URI that may be used to retrieve a CRL.
#[cfg(feature = "remote")]
async fn fetch_crl(pe: &PkiEnvironment, uri: &str, timeout_in_secs: u64) -> Result<Vec<u8>> {
    if !uri.starts_with("http") {
        debug!("Ignored non-HTTP URI presented for CRL retrieval",);
        return Err(Error::InvalidUriScheme);
    }

    if pe.check_blocklist(uri) {
        info!("{} is on the blocklist", uri);
        return Err(Error::UriOnBlocklist);
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_in_secs))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            debug!("Failed to prepare HTTP client to retrieve CRL: {}", e);
            return Err(Error::ResourceUnchanged);
        }
    };

    // Read saved last modified time, if any, for use in avoiding unnecessary download below
    let h = pe.get_last_modified(uri);

    let response = if let Some(h) = h {
        client.get(uri).header("If-Modified-Since", h).send().await
    } else {
        client.get(uri).send().await
    };
    match response {
        Ok(response) => {
            // seen it before, skip it now
            if 304 == response.status() {
                return Err(Error::ResourceUnchanged);
            }

            let last_mod = response.headers().get("Last-Modified");
            if let Some(last_mod) = last_mod {
                if let Ok(last_modified) = last_mod.to_str() {
                    pe.set_last_modified(uri, last_modified);
                }
            }

            let b = response.bytes().await;
            match &b {
                Ok(bytes) => Ok(bytes.clone().to_vec()),
                Err(e) => {
                    debug!("Failed to retrieve CRL bytes from {} with {}", uri, e);
                    Err(Error::NetworkError)
                }
            }
        }
        Err(e) => {
            debug!("Failed to fetch CRL from {}: {:?}", uri, e);
            pe.add_to_blocklist(uri);
            Err(Error::NetworkError)
        }
    }
}

/// ClassifyCertificate takes a certificate and returns a CertRevType value.
///  - CaDp is returned if basicConstraints is present and isCA is true AND a CRL DP extension is present.
///  - EeDp is returned if basicConstraints is absent or isCA is false AND a CRL DP extension is present.
///  - Ca is returned if basicConstraints is present and isCA is true AND a CRL DP extension is not present.
///  - Ee is returned if basicConstraints is absent or isCA is false AND a CRL DP extension is not present.
fn classify_certificate(cert: &PDVCertificate) -> CertRevType {
    let is_ca = if let Ok(Some(PDVExtension::BasicConstraints(bc))) =
        cert.get_extension(&ID_CE_BASIC_CONSTRAINTS)
    {
        bc.ca
    } else {
        false
    };

    let has_crldp = matches!(
        cert.get_extension(&ID_CE_CRL_DISTRIBUTION_POINTS),
        Ok(Some(PDVExtension::CrlDistributionPoints(_crldp)))
    );
    if is_ca && has_crldp {
        CertRevType::CaDp
    } else if !is_ca && has_crldp {
        CertRevType::EeDp
    } else if is_ca {
        CertRevType::Ca
    } else {
        CertRevType::Ee
    }
}

// Flag set used in get_crl_info to classify a CRL
flags! {
    enum CrlQuestions: u8 {
        EeOnly,
        CaOnly,
        AaOnly,
        Delta,
        Partitioned,
        Indirect,
        SomeReasons
    }
}
type CrlQuestionairre = FlagSet<CrlQuestions>;

pub(crate) fn get_crl_info(crl: &CertificateList) -> Result<CrlInfo> {
    let this_update = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
    let next_update = crl
        .tbs_cert_list
        .next_update
        .map(|nu| nu.to_unix_duration().as_secs());
    let issuer_name_blob = match crl.tbs_cert_list.issuer.to_der() {
        Ok(enc) => enc,
        Err(_e) => return Err(Error::Unrecognized),
    };
    let issuer_name = name_to_string(&crl.tbs_cert_list.issuer);
    let sig_alg_blob = match crl.signature_algorithm.to_der() {
        Ok(enc) => enc,
        Err(_e) => return Err(Error::Unrecognized),
    };
    let mut exts_blob = None;
    if let Some(crl_exts) = &crl.tbs_cert_list.crl_extensions {
        exts_blob = match crl_exts.to_der() {
            Ok(enc) => Some(enc),
            Err(_e) => return Err(Error::Unrecognized),
        };
    }
    let mut idp_blob: Option<Vec<u8>> = None;
    let mut idp_name: Option<String> = None;
    let mut skid: Option<Vec<u8>> = None;

    let mut questionnaire = CrlQuestionairre::default();

    //SKID, delta, idp
    if let Some(exts) = &crl.tbs_cert_list.crl_extensions {
        for ext in exts.iter() {
            match ext.extn_id {
                ID_CE_ISSUING_DISTRIBUTION_POINT => {
                    idp_blob = Some(ext.extn_value.as_bytes().to_vec());
                    let idp = match IssuingDistributionPoint::from_der(ext.extn_value.as_bytes()) {
                        Ok(idp) => idp,
                        Err(e) => {
                            return Err(Error::Asn1Error(e));
                        }
                    };

                    match &idp.distribution_point {
                        Some(DistributionPointName::FullName(gns)) => {
                            for gn in gns {
                                if let GeneralName::DirectoryName(dn) = gn {
                                    idp_name = Some(name_to_string(dn));
                                    break;
                                }
                            }
                            if idp_name.is_none() {
                                // not supporting non-DN DPs
                                return Err(Error::Unrecognized);
                            }
                        }
                        Some(DistributionPointName::NameRelativeToCRLIssuer(_unsupported)) => {
                            // Not supporting name relative to issuer
                            return Err(Error::Unrecognized);
                        }
                        _ => {}
                    }

                    if idp.distribution_point.is_some() {
                        questionnaire |= CrlQuestions::Partitioned;
                    }

                    if idp.indirect_crl {
                        questionnaire |= CrlQuestions::Indirect;
                    }
                    if let Some(_osr) = &idp.only_some_reasons {
                        questionnaire |= CrlQuestions::SomeReasons;
                    }
                    if idp.only_contains_user_certs {
                        questionnaire |= CrlQuestions::EeOnly;
                    }
                    if idp.only_contains_ca_certs {
                        questionnaire |= CrlQuestions::CaOnly;
                    }
                    if idp.only_contains_attribute_certs {
                        questionnaire |= CrlQuestions::AaOnly;
                    }
                } // end ID_CE_ISSUING_DISTRIBUTION_POINT
                ID_CE_AUTHORITY_KEY_IDENTIFIER => {
                    if let Ok(akid) = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes()) {
                        if let Some(kid) = akid.key_identifier {
                            skid = Some(kid.as_bytes().to_vec());
                        }
                    }
                }
                ID_CE_DELTA_CRL_INDICATOR => {
                    questionnaire |= CrlQuestions::Delta;
                }
                _ => {}
            }
        } //end iterating over extensions
    }

    if questionnaire.contains(CrlQuestions::AaOnly) {
        //XXX-DEFER Do work here to support ACRL, AARL, etc.
        return Err(CrlIncompatible);
    }

    let coverage = if questionnaire.contains(CrlQuestions::EeOnly) {
        CrlCoverage::EeOnly
    } else if questionnaire.contains(CrlQuestions::CaOnly) {
        CrlCoverage::CaOnly
    } else {
        CrlCoverage::All
    };

    let authority = if questionnaire.contains(CrlQuestions::Indirect) {
        CrlAuthority::Indirect
    } else {
        CrlAuthority::Direct
    };

    let scope = if questionnaire.contains(CrlQuestions::Partitioned) {
        if questionnaire.contains(CrlQuestions::Delta) {
            CrlScope::DeltaDp
        } else {
            CrlScope::Dp
        }
    } else if questionnaire.contains(CrlQuestions::Delta) {
        CrlScope::Delta
    } else {
        CrlScope::Complete
    };

    //determine reasons
    let reasons = if questionnaire.contains(CrlQuestions::SomeReasons) {
        CrlReasons::SomeReasons
    } else {
        CrlReasons::AllReasons
    };

    let type_info = CrlType {
        scope,
        coverage,
        authority,
        reasons,
    };

    Ok(CrlInfo {
        type_info,
        skid,
        this_update,
        next_update,
        issuer_name,
        issuer_name_blob,
        sig_alg_blob,
        exts_blob,
        idp_name,
        idp_blob,
        filename: None,
    })
}

fn validate_crl_issuer_name(
    cert: &PDVCertificate,
    crl_info: &CrlInfo,
) -> Result<Option<DistributionPoint>> {
    // 4-b) Validate CRL issuer name (discard CRL upon failure)
    //			i.	One of the names in a CRL DP crlIssuer field or the cert issuer shall match the CRL issuer.
    //				If a CRL DP produced the match, set the active CRLDP state variable to the CRL DP containing
    //				matching crlIssuer field.
    let crl_dp = match cert.get_extension(&ID_CE_CRL_DISTRIBUTION_POINTS) {
        Ok(Some(PDVExtension::CrlDistributionPoints(crl_dp))) => crl_dp,
        _ => match Name::from_der(&crl_info.issuer_name_blob) {
            Ok(n) => {
                if compare_names(&cert.decoded_cert.tbs_certificate.issuer, &n) {
                    return Ok(None);
                } else {
                    return Err(Error::CrlIncompatible);
                }
            }
            Err(e) => {
                return Err(Error::Asn1Error(e));
            }
        },
    };

    for dp in &crl_dp.0 {
        if let Some(gns) = &dp.crl_issuer {
            for gn in gns {
                if let GeneralName::DirectoryName(dn) = gn {
                    if let Ok(enc_dn) = dn.to_der() {
                        if enc_dn == crl_info.issuer_name_blob {
                            return Ok(Some(dp.clone()));
                        }
                    }
                }
            }
        }
    }

    match Name::from_der(&crl_info.issuer_name_blob) {
        Ok(n) => {
            if compare_names(&cert.decoded_cert.tbs_certificate.issuer, &n) {
                Ok(None)
            } else {
                Err(Error::CrlIncompatible)
            }
        }
        Err(e) => Err(Error::Asn1Error(e)),
    }
}

fn is_general_name_in_general_names(lhs: &GeneralNames, rhs: &GeneralName) -> bool {
    for gn in lhs {
        if gn == rhs {
            return true;
        }
    }
    false
}

fn at_least_one_general_name_in_common(
    gns_from_crl_dp: &GeneralNames,
    gns_from_idp: &GeneralNames,
) -> bool {
    for gn in gns_from_idp {
        if is_general_name_in_general_names(gns_from_crl_dp, gn) {
            return true;
        }
    }
    false
}

fn validate_distribution_point(
    dps_from_crl_dp: Option<&CrlDistributionPoints>,
    crl_info: &CrlInfo,
    cert_type: CertRevType,
    target_cert: &PDVCertificate,
    collected_reasons: &mut ReasonFlags,
) -> Result<()> {
    let active_crl_dp = validate_crl_issuer_name(target_cert, crl_info)?;

    //	4-c) Validate DP (discard CRL upon failure)
    //			i.	If the active CRL DP is set and an IDP w/distribution point field is present in the CRL, one
    //				of the names in the active CRL DP shall match one of the names in the IDP DP.  If the active
    //				CRL DP is not set and an IDP w/distribution point field is present, one of the names in a CRL
    //				DP shall match one of the names in the IDP DP and the active CRL DP should be set to the CRL
    //				DP that matches the IDP.
    //			ii.	If reasons field is present in the active CRL DP, the onlySomeReasons field of the IDP shall
    //				be absent or contain at least one of the reason codes asserted in the CRL DP
    if CrlScope::Dp == crl_info.type_info.scope || CrlScope::DeltaDp == crl_info.type_info.scope {
        //if it's a DP CRL but cert has no CRL DP then return false
        if dps_from_crl_dp.is_none() || crl_info.idp_blob.is_none() {
            return Err(Error::CrlIncompatible);
        }

        let idp_blob = if let Some(idp_blob) = crl_info.idp_blob.as_ref() {
            idp_blob
        } else {
            return Err(Error::Unrecognized);
        };

        let idp = match IssuingDistributionPoint::from_der(idp_blob.as_slice()) {
            Ok(idp) => idp,
            Err(_e) => return Err(Error::Unrecognized),
        };

        let gns_from_idp = match idp.distribution_point {
            Some(DistributionPointName::FullName(gns)) => gns,
            Some(DistributionPointName::NameRelativeToCRLIssuer(_unsupported)) => {
                return Err(Error::Unrecognized)
            }
            _ => {
                // should not occur given the CsDp or CsDeltaDp scope
                return Err(Error::Unrecognized);
            }
        };

        let mut found_match = false;
        if let Some(ref crl_dp) = active_crl_dp {
            //if there's an active CRL DP, i.e. on that produced a match in the CRL issuer validation
            //function - then require that specific DP to match here

            if let Some(DistributionPointName::FullName(gns_from_crl_dp)) =
                &crl_dp.distribution_point
            {
                found_match = at_least_one_general_name_in_common(gns_from_crl_dp, &gns_from_idp);
            }
        } else {
            //otherwise, any DP can match
            if let Ok(Some(PDVExtension::CrlDistributionPoints(crl_dp))) =
                target_cert.get_extension(&ID_CE_CRL_DISTRIBUTION_POINTS)
            {
                for dp in &crl_dp.0 {
                    if let Some(DistributionPointName::FullName(gns_from_crl_dp)) =
                        &dp.distribution_point
                    {
                        found_match =
                            at_least_one_general_name_in_common(gns_from_crl_dp, &gns_from_idp);
                        if found_match {
                            break;
                        }
                    }
                }
            }
        }

        //if no DP matches then return false
        if !found_match {
            return Err(Error::CrlIncompatible);
        }
    }

    if let Some(idp_blob) = &crl_info.idp_blob {
        let idp = match IssuingDistributionPoint::from_der(idp_blob) {
            Ok(idp) => idp,
            Err(e) => return Err(Error::Asn1Error(e)),
        };

        if idp.only_contains_attribute_certs {
            return Err(Error::CrlIncompatible);
        }

        if idp.only_contains_ca_certs
            && (CertRevType::Ee == cert_type || CertRevType::EeDp == cert_type)
        {
            return Err(Error::CrlIncompatible);
        }

        if idp.only_contains_user_certs
            && (CertRevType::Ca == cert_type || CertRevType::CaDp == cert_type)
        {
            return Err(Error::CrlIncompatible);
        }

        if AllReasons != crl_info.type_info.reasons {
            if let Some(idp_reasons) = idp.only_some_reasons {
                *collected_reasons = idp_reasons;

                if let Some(ref crl_dp) = active_crl_dp {
                    if let Some(crldp_reasons) = crl_dp.reasons {
                        if (crldp_reasons & idp_reasons).is_empty() {
                            return Err(CrlIncompatible);
                        } else {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn validate_crl_authority(target_cert: &PDVCertificate, crl_info: &CrlInfo) -> Result<bool> {
    //	d) Validate CRL authority (discard CRL upon failure)
    //		If the CRL issuer name does not match the cert issuer name, the indirectCRL field must be present
    //		in the IDP.

    let enc_iss = match target_cert.decoded_cert.tbs_certificate.issuer.to_der() {
        Ok(b) => b,
        Err(_e) => return Err(Error::Unrecognized),
    };

    if enc_iss != crl_info.issuer_name_blob
        && CrlAuthority::Indirect != crl_info.type_info.authority
    {
        Ok(false)
    } else {
        Ok(true)
    }
}

fn verify_crl(
    pe: &PkiEnvironment,
    crl_buf: &[u8],
    issuer_cert: &Certificate,
    cpr: &mut CertificationPathResults,
) -> Result<()> {
    let defer_crl = match DeferDecodeSigned::from_der(crl_buf) {
        Ok(crl) => crl,
        Err(_e) => return Err(Error::Unrecognized),
    };

    let r = pe.verify_signature_message(
        pe,
        &defer_crl.tbs_field,
        defer_crl.signature.raw_bytes(),
        &defer_crl.signature_algorithm,
        &issuer_cert.tbs_certificate.subject_public_key_info,
    );
    if let Err(e) = r {
        log_error_for_subject(
            issuer_cert,
            format!("CRL signature verification error: {:?}", e).as_str(),
        );
        set_validation_status(cpr, PathValidationStatus::SignatureVerificationFailure);
        return Err(Error::PathValidation(
            PathValidationStatus::SignatureVerificationFailure,
        ));
    }
    Ok(())
}

/// check_entry_extensions inspects the extensions in a CRL entry. invalidity date and reasons are just
/// informational, so presence is fine. hold instruction is simply ignored with corresponding certificate
/// treated as revoked. Presence of any other critical extension is cause to discard the CRL. The
/// certificate issuer extension is assumed to have been checked already via  certificate_issuer_extension_present.
fn check_entry_extensions(rc: &RevokedCert) -> Result<()> {
    let exts_to_ignore = [
        ID_CE_INVALIDITY_DATE,
        ID_CE_CRL_REASONS,
        ID_CE_HOLD_INSTRUCTION_CODE,
    ];
    if let Some(exts) = &rc.crl_entry_extensions {
        for e in exts {
            if e.critical && !exts_to_ignore.contains(&e.extn_id) {
                return Err(Error::CrlIncompatible);
            }
        }
    }
    Ok(())
}

fn check_crl_extensions(exts: &Extensions) -> Result<()> {
    let exts_to_ignore = [
        ID_CE_ISSUING_DISTRIBUTION_POINT,
        ID_CE_DELTA_CRL_INDICATOR,
        ID_CE_FRESHEST_CRL,
        ID_CE_CRL_NUMBER,
        ID_CE_AUTHORITY_KEY_IDENTIFIER,
    ];
    for e in exts {
        if e.critical && !exts_to_ignore.contains(&e.extn_id) {
            return Err(Error::CrlIncompatible);
        }
    }
    Ok(())
}

/// certificate_issuer_extension_present returns true if a certificate issuer extension is found
/// in the presented RevokedCert instance and false otherwise.
fn certificate_issuer_extension_present(rc: &RevokedCert) -> bool {
    if let Some(exts) = &rc.crl_entry_extensions {
        for e in exts {
            if e.extn_id == ID_CE_CERTIFICATE_ISSUER {
                return true;
            }
        }
    }
    false
}

pub(crate) fn check_crl_validity(toi: u64, crl: &CertificateList) -> Result<()> {
    if 0 != toi {
        let tu = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
        if tu > toi {
            info!("Discarding CRL from {} as having this update time({}) later than time of interest ({})", name_to_string(&crl.tbs_cert_list.issuer),tu, toi);
            return Err(Error::CrlIncompatible);
        }
        if let Some(nu) = crl.tbs_cert_list.next_update {
            if nu.to_unix_duration().as_secs() < toi {
                info!("Discarding CRL from {} as having next update time({}) earlier than time of interest ({})", name_to_string(&crl.tbs_cert_list.issuer),tu, toi);
                return Err(Error::CrlIncompatible);
            }
        }
    }
    Ok(())
}

fn check_crl_sign(cert: &Certificate) -> Result<()> {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.extn_id == ID_CE_KEY_USAGE {
                if let Ok(ku) = KeyUsage::from_der(ext.extn_value.as_bytes()) {
                    // (n)  If a key usage extension is present, verify that the
                    //      keyCertSign bit is set.
                    if !ku.0.contains(KeyUsages::CRLSign) {
                        error!("crlSign is not set in key usage extension");
                        return Err(Error::PathValidation(PathValidationStatus::InvalidKeyUsage));
                    } else {
                        return Ok(());
                    }
                } else {
                    error!("key usage extension could not be parsed");
                    return Err(Error::PathValidation(PathValidationStatus::InvalidKeyUsage));
                }
            }
        }
    }
    error!("key usage extension is missing");
    Err(Error::PathValidation(PathValidationStatus::InvalidKeyUsage))
}

/// process_crl takes a CRL that is processed relative to a given target certificate and issuer
/// certificate.
#[allow(clippy::too_many_arguments)]
pub(crate) fn process_crl(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cpr: &mut CertificationPathResults,
    target_cert: &PDVCertificate,
    issuer_cert: &Certificate,
    result_index: usize,
    crl_buf: &[u8],
    uri: Option<&str>,
) -> Result<()> {
    // Verify then parse and classify the CRL
    verify_crl(pe, crl_buf, issuer_cert, cpr)?;
    check_crl_sign(issuer_cert)?;

    let crl = match CertificateList::from_der(crl_buf) {
        Ok(crl) => crl,
        Err(e) => {
            if let Some(uri) = uri {
                error!("Failed to parse CRL from {} with {}", uri, e);
            } else {
                error!("Failed to parse CRL from with {}", e);
            }
            add_failed_crl(cpr, crl_buf, result_index);
            return Err(Error::Asn1Error(e));
        }
    };
    let crl_info = get_crl_info(&crl)?;

    if let Some(uri) = uri {
        if let Err(e) = pe.add_crl(crl_buf, &crl, uri) {
            error!("Failed to save CRL with: {}", e);
        }
    }

    //Classify the certificate as DP/not DP and CA/EE and harvest DPs, if any
    let cert_type = classify_certificate(target_cert);
    let dps_from_crl_dp = match target_cert.get_extension(&ID_CE_CRL_DISTRIBUTION_POINTS) {
        Ok(Some(PDVExtension::CrlDistributionPoints(crldp))) => Some(crldp),
        _ => None,
    };

    //4-a) confirm that the CRL type and cert type are compatible
    if !COMPATIBLE_SCOPE[(cert_type as usize, crl_info.type_info.scope as usize)]
        || !COMPATIBLE_COVERAGE[(cert_type as usize, crl_info.type_info.coverage as usize)]
    {
        info!("Discarding CRL from {} as having incompatible scope or coverage for certificate issued to {}", name_to_string(&crl.tbs_cert_list.issuer), name_to_string(&target_cert.decoded_cert.tbs_certificate.subject));
        return Err(Error::CrlIncompatible);
    }

    //4-b) validate the CRL issuer name (validate_crl_issuer_name is called by validate_distribution_point)
    //4-c) Validate DP (sets activeCRLDP as necessary)
    let mut collected_reasons = match ReasonFlags::new(0) {
        Ok(rf) => rf,
        Err(_e) => {
            info!(
                "Discarding CRL from {} due to failure to prepare ReasonFlags",
                name_to_string(&crl.tbs_cert_list.issuer)
            );
            return Err(Error::Unrecognized);
        }
    };
    if let Err(_e) = validate_distribution_point(
        dps_from_crl_dp,
        &crl_info,
        cert_type,
        target_cert,
        &mut collected_reasons,
    ) {
        info!("Discarding CRL from {} as having incompatible distribution point for certificate issued to {}", name_to_string(&crl.tbs_cert_list.issuer), name_to_string(&target_cert.decoded_cert.tbs_certificate.subject));
        return Err(Error::CrlIncompatible);
    }

    //4-d) Validate CRL authority
    if let Err(_e) = validate_crl_authority(target_cert, &crl_info) {
        info!(
            "Discarding CRL from {} as having incompatible authority for certificate issued to {}",
            name_to_string(&crl.tbs_cert_list.issuer),
            name_to_string(&target_cert.decoded_cert.tbs_certificate.subject)
        );
        return Err(Error::CrlIncompatible);
    }

    let toi = get_time_of_interest(cps);
    check_crl_validity(toi, &crl)?;

    if let Some(exts) = &crl.tbs_cert_list.crl_extensions {
        if let Err(_e) = check_crl_extensions(exts) {
            info!(
                "Discarding CRL from {} due to unrecognized critical extension",
                name_to_string(&crl.tbs_cert_list.issuer)
            );
            return Err(Error::UnsupportedCrlExtension);
        }
    }

    if let Some(revoked_certificates) = crl.tbs_cert_list.revoked_certificates {
        for rc in revoked_certificates {
            // if we detect this is an indirect CRL (which should have been determined already by inspection
            // of the IDP extension, discard the CRL. this check could be dropped is sufficiently satisfied
            // that IDP check is good enough.
            if certificate_issuer_extension_present(&rc) {
                info!("Discarding CRL from {} due to presence of certificate issuer CRL entry extension", name_to_string(&crl.tbs_cert_list.issuer));
                return Err(Error::UnsupportedIndirectCrl);
            }

            if rc.serial_number == target_cert.decoded_cert.tbs_certificate.serial_number {
                // this is probably not a useful check. will change ultimate error from revoked to
                // status not determined, most likely.
                if let Err(_e) = check_entry_extensions(&rc) {
                    info!(
                        "Discarding CRL from {} due to unrecognized critical CRL entry extension",
                        name_to_string(&crl.tbs_cert_list.issuer)
                    );
                    return Err(Error::UnsupportedCrlEntryExtension);
                }

                match rc.to_der() {
                    Ok(enc_entry) => {
                        add_crl_entry(cpr, enc_entry, result_index);
                    }
                    Err(e) => {
                        error!(
                            "Failed to encode CRL entry for logging purposes with: {}",
                            e
                        );
                    }
                };

                if let Some(nu) = crl.tbs_cert_list.next_update {
                    pe.add_status(
                        target_cert,
                        nu.to_unix_duration().as_secs(),
                        PathValidationStatus::CertificateRevoked,
                    );
                }
                return Err(Error::PathValidation(
                    PathValidationStatus::CertificateRevoked,
                ));
            }
        }
    }
    if let Some(nu) = crl.tbs_cert_list.next_update {
        pe.add_status(
            target_cert,
            nu.to_unix_duration().as_secs(),
            PathValidationStatus::Valid,
        );
    }
    Ok(())
}

#[cfg(feature = "remote")]
pub(crate) async fn check_revocation_crl_remote(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cpr: &mut CertificationPathResults,
    target_cert: &PDVCertificate,
    issuer_cert: &Certificate,
    pos: usize,
) -> PathValidationStatus {
    let mut target_status = PathValidationStatus::RevocationStatusNotDetermined;
    let cur_cert_subject = name_to_string(&target_cert.decoded_cert.tbs_certificate.subject);
    let crl_dps = get_crl_dps(target_cert);
    if crl_dps.is_empty() {
        info!(
            "No CRL DPs found for {}",
            name_to_string(&target_cert.decoded_cert.tbs_certificate.subject)
        );
    } else {
        let timeout = get_crl_timeout(cps);
        for crl_dp in crl_dps {
            debug!("Fetching CRL from {}", crl_dp.as_str());

            let crl = match fetch_crl(pe, crl_dp.as_str(), timeout).await {
                Ok(crl) => crl,
                Err(_e) => continue,
            };
            debug!("Processing CRL from {}", crl_dp.as_str());

            match process_crl(
                pe,
                cps,
                cpr,
                target_cert,
                issuer_cert,
                pos,
                &crl,
                Some(crl_dp.as_str()),
            ) {
                Ok(_ok) => {
                    target_status = {
                        add_crl(cpr, crl.as_slice(), pos);
                        info!("Determined revocation status (valid) using CRL for certificate issued to {}", cur_cert_subject);
                        PathValidationStatus::Valid
                    }
                }
                Err(e) => {
                    if Error::PathValidation(PathValidationStatus::CertificateRevoked) == e {
                        add_crl(cpr, crl.as_slice(), pos);
                        info!("Determined revocation status (revoked) using CRL for certificate issued to {}", cur_cert_subject);
                        return PathValidationStatus::CertificateRevoked;
                    } else {
                        info!("Failed to determine revocation status using CRL for certificate issued to {} with {}", cur_cert_subject, e);
                        add_failed_crl(cpr, crl.as_slice(), pos);
                    }
                }
            };
            if target_status != PathValidationStatus::RevocationStatusNotDetermined {
                // no need to consider additional CRL DPs
                break;
            }
        }
    }
    target_status
}

#[cfg(feature = "remote")]
#[tokio::test]
async fn fetch_crl_test() {
    use crate::populate_5280_pki_environment;
    use crate::CrlSourceFolders;
    use std::path::PathBuf;
    let mut pe = PkiEnvironment::default();
    pe.clear_all_callbacks();
    populate_5280_pki_environment(&mut pe);

    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let f = d.join("tests/examples/fetch_crl_test");
    let crl_source = CrlSourceFolders::new(f.as_path().to_str().unwrap());
    if crl_source.index_crls(1647011592).is_err() {
        panic!("Failed to index CRLs")
    }
     pe.add_crl_source(Box::new(crl_source.clone()));
     pe.add_revocation_cache(Box::new(crl_source.clone()));
     pe.add_check_remote(Box::new(crl_source.clone()));

    let r = fetch_crl(&pe, "ldap://ldap.scheme/", 60).await;
    assert!(r.is_err());
    assert_eq!(Some(Error::InvalidUriScheme), r.err());
    pe.add_to_blocklist("http://blocklist.test");
    let r = fetch_crl(&pe, "http://blocklist.test", 60).await;
    assert!(r.is_err());
    assert_eq!(Some(Error::UriOnBlocklist), r.err());

    let f = d.join("tests/examples/fetch_crl_test/last_modified_map.json");
    if std::path::Path::exists(&f) {
        tokio::fs::remove_file(f.to_str().unwrap()).await.unwrap();
    }

    let r = fetch_crl(
        &pe,
        "http://crl.sectigo.com/SectigoRSAOrganizationValidationSecureServerCA.crl",
        60,
    )
    .await;
    assert!(r.is_ok());
    let r = fetch_crl(
        &pe,
        "http://crl.sectigo.com/SectigoRSAOrganizationValidationSecureServerCA.crl",
        60,
    )
    .await;
    assert!(r.is_err());
    assert_eq!(Some(Error::ResourceUnchanged), r.err());

    let _ = tokio::fs::remove_file(f.to_str().unwrap()).await;
}
