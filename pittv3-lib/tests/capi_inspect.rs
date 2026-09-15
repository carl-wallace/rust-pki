//! Integration test for the intermediate half of a Windows store selection in `inspect_args`.
//!
//! `load_trust_anchors` reads `capi_ta_stores`, so an inspection always showed a CAPI selection's
//! anchors; the CA half was read by validation alone, and the Inspect view listed no
//! intermediates at all. The store is live, so what it holds varies by machine -- the test asserts
//! that the inspection holds whatever the store does rather than any particular count.
#![cfg(all(windows, feature = "capi"))]

use certval::{CertSource, CertVector};
use pittv3_lib::args::Pittv3Args;
use pittv3_lib::options_std::inspect_args;
use pittv3_lib::std_utils::load_capi_ca_stores;

/// Current user rather than local machine: the machine stores need elevation even to read.
const CA_STORE: &str = "CurrentUser\\CA";

#[test]
fn inspection_includes_capi_ca_stores() {
    let specs = vec![CA_STORE.to_string()];
    let expected = load_capi_ca_stores(&specs, &mut CertSource::new()).unwrap();

    let args = Pittv3Args {
        capi_ca_stores: specs,
        ..Default::default()
    };
    let inspected = inspect_args(&args).unwrap_or_else(|e| panic!("inspection failed: {e:?}"));

    assert_eq!(
        inspected.certs.len(),
        expected,
        "the inspection did not hold what {CA_STORE} holds"
    );
}
