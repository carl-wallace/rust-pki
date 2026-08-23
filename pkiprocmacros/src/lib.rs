//! Procedural macros that generate typed accessors for the `certval` certification path
//! validation library.
//!
//! `certval` carries path-processing state in two string-keyed maps: `CertificationPathSettings`,
//! which holds the inputs to a validation, and `CertificationPathResults`, which holds what the
//! validation produced. Both store their values in an enum that has one variant per value type
//! (`CertificationPathProcessingTypes` and `CertificationPathResultsTypes` respectively), so
//! reading one entry by hand means a key lookup followed by a variant match, and writing one means
//! wrapping the value back up in the right variant. The macros here emit that pair of methods from
//! a single line, which is why `certval` declares roughly sixty settings and results without a
//! hand-written accessor among them.
//!
//! | Macro | Implements on | Getter returns |
//! |---|---|---|
//! | [`cps_gets_and_sets`] | `CertificationPathSettings` | `Option<T>` |
//! | [`cps_gets_and_sets_with_default`] | `CertificationPathSettings` | `T`, falling back to a default |
//! | [`cpr_gets_and_sets`] | `CertificationPathResults` | `Option<T>` |
//! | [`cpr_gets_and_sets_with_default`] | `CertificationPathResults` | `T`, falling back to a default |
//!
//! # Naming
//!
//! Every macro derives the method names from the constant it is given by **dropping the first three
//! characters and lowercasing the rest**, then prefixing `get_` and `set_`. The three characters are
//! the `PS_` or `PR_` tag the constants carry, so `PS_CHECK_REVOCATION_STATUS` yields
//! `get_check_revocation_status` and `set_check_revocation_status`. The slice is unconditional: a
//! name without a three-character prefix produces a correspondingly wrong pair of method names.
//!
//! # Variant selection
//!
//! The enum variant used to store the value is derived from the *type name* given to the macro:
//!
//! - `bool` becomes `Bool`
//! - a name whose characters after the first are all digits — `u8`, `u32`, `u64` — is uppercased,
//!   giving `U8`, `U32`, `U64`
//! - anything else is used verbatim, so `ObjectIdentifierSet` selects the `ObjectIdentifierSet`
//!   variant
//!
//! The enclosing enum must therefore carry a variant of that name, and it must hold exactly the type
//! named in the invocation. Neither condition is checked here — a mismatch surfaces as an ordinary
//! compile error in the expanded code.
//!
//! # Scope
//!
//! These macros are not usable on their own. Every expansion names types that live in `certval`, so
//! an invocation only compiles inside a crate that provides them; `certval` depends on this crate
//! so this crate cannot depend `certval`. That is why the example on each macro's own page is shown
//! rather than compiled.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use quote::quote;
use syn::parse::ParseStream;
use syn::parse::{Parse, Result};
use syn::{Expr, Ident, Token};

type ValueName = Ident;
type ValueType = Ident;
type DefaultValue = Expr;

/// Signature contains the results of parsing a cps_gets_and_sets definition, i.e., the
/// name of a value stored in a CertificationPathSettings map and the corresponding type.
struct Signature {
    value_name: ValueName,
    value_type: ValueType,
}

/// Syntax contains the components of a cps_gets_and_sets, i.e., a value name, a comma and
/// a value type. For example:
/// ```text
/// cps_gets_and_sets!(PS_EXTENDED_KEY_USAGE, ObjectIdentifierSet);
/// ```
struct Syntax {
    value_name: ValueName,
    _comma_token: Token!(,),
    value_type: ValueType,
}

/// is_string_numeric is used to determine if a string value contains only numeric characters.
/// It is used to process a slice that omits the first character, i.e., in order to identify
/// types like u8, u32, etc.
fn is_string_numeric(str: &str) -> bool {
    for c in str.chars() {
        if !c.is_numeric() {
            return false;
        }
    }
    true
}

impl Parse for Signature {
    fn parse(stream: ParseStream) -> Result<Self> {
        if stream.is_empty() {
            panic!("Write full function signature.");
        }

        let syntax = Syntax {
            value_name: stream.parse().unwrap(),
            _comma_token: stream.parse().unwrap(),
            value_type: stream.parse().unwrap(),
        };

        Ok(Signature {
            value_name: syntax.value_name,
            value_type: syntax.value_type,
        })
    }
}

/// Generates a getter/setter pair on `CertificationPathSettings` for one setting.
///
/// Takes a setting name and the type of the value it stores. The getter answers `None` when the
/// setting is absent *and* when it is present under a different variant; use
/// [`cps_gets_and_sets_with_default`] where a caller should see a value either way.
///
/// ```text
/// cps_gets_and_sets!(PS_CERTIFICATION_AUTHORITY_FOLDER, String);
/// ```
///
/// expands to:
///
/// ```text
/// impl CertificationPathSettings {
///     pub fn get_certification_authority_folder(&self) -> Option<String> { ... }
///     pub fn set_certification_authority_folder(&mut self, v: String) { ... }
/// }
/// ```
///
/// The setter stores the key as an owned `String`, since the settings map is keyed by `String`.
#[proc_macro]
pub fn cps_gets_and_sets(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let signature = syn::parse_macro_input!(input as Signature);
    let flag = signature.value_name;
    let return_t = signature.value_type;

    let flag_str = format!("{flag}")[3..].to_lowercase();
    let getter_str = format!("get_{flag_str}");
    let setter_str = format!("set_{flag_str}");
    let cps_type_str = format!("{return_t}");
    let mut upper_cps_type_str = if is_string_numeric(&cps_type_str[1..]) {
        cps_type_str.to_uppercase()
    } else {
        cps_type_str
    };
    if upper_cps_type_str == "bool" {
        upper_cps_type_str = "Bool".to_string();
    }
    let getter = syn::Ident::new(&getter_str, flag.span());
    let setter = syn::Ident::new(&setter_str, flag.span());
    let cps_type = syn::Ident::new(&upper_cps_type_str, return_t.span());

    let getter_comment = format!(
        "`{getter_str}` is used to retrieve `{flag}` items from a [`CertificationPathSettings`] instance"
    );
    let setter_comment = format!(
        "`{setter_str}` is used to set `{flag}` items in a [`CertificationPathSettings`] instance"
    );

    let tokens = quote! {
        impl CertificationPathSettings {
            #[doc = #getter_comment]
            pub fn #getter(&self)->Option<#return_t>{
                if self.0.contains_key(#flag) {
                    return match &self.0[#flag] {
                        CertificationPathProcessingTypes::#cps_type(v) => Some(v.clone()),
                        _ => None,
                    };
                }
                None
            }
            #[doc = #setter_comment]
            pub fn #setter(&mut self, v: #return_t){
                self.0.insert(
                    #flag.to_string(),
                    CertificationPathProcessingTypes::#cps_type(v),
                );
            }
        }
    };
    tokens.into()
}

/// Generates a getter/setter pair on `CertificationPathResults` for one result value.
///
/// The counterpart of [`cps_gets_and_sets`] for the results map: same naming and variant rules, but
/// the methods land on `CertificationPathResults` and the value is wrapped in
/// `CertificationPathResultsTypes`.
///
/// ```text
/// cpr_gets_and_sets!(PR_FAILURE_INDEX, u32);
/// ```
///
/// expands to:
///
/// ```text
/// impl CertificationPathResults {
///     pub fn get_failure_index(&self) -> Option<u32> { ... }
///     pub fn set_failure_index(&mut self, v: u32) { ... }
/// }
/// ```
///
/// The setter stores the key as `&'static str` rather than an owned `String`, because the results
/// map is keyed by `&'static str`.
#[proc_macro]
pub fn cpr_gets_and_sets(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let signature = syn::parse_macro_input!(input as Signature);
    let flag = signature.value_name;
    let return_t = signature.value_type;

    let flag_str = format!("{flag}")[3..].to_lowercase();
    let getter_str = format!("get_{flag_str}");
    let setter_str = format!("set_{flag_str}");
    let cpr_type_str = format!("{return_t}");
    let mut upper_cpr_type_str = if is_string_numeric(&cpr_type_str[1..]) {
        cpr_type_str.to_uppercase()
    } else {
        cpr_type_str
    };
    if upper_cpr_type_str == "bool" {
        upper_cpr_type_str = "Bool".to_string();
    }
    let getter = syn::Ident::new(&getter_str, flag.span());
    let setter = syn::Ident::new(&setter_str, flag.span());
    let cpr_type = syn::Ident::new(&upper_cpr_type_str, return_t.span());

    let getter_comment = format!(
        "`{getter_str}` is used to retrieve `{flag}` items from a [`CertificationPathResults`] instance"
    );
    let setter_comment = format!(
        "`{setter_str}` is used to set `{flag}` items in a [`CertificationPathResults`] instance"
    );

    let tokens = quote! {
        impl CertificationPathResults {
            #[doc = #getter_comment]
            pub fn #getter(&self)->Option<#return_t>{
                if self.0.contains_key(#flag) {
                    return match &self.0[#flag] {
                        CertificationPathResultsTypes::#cpr_type(v) => Some(v.clone()),
                        _ => None,
                    };
                }
                None
            }
            #[doc = #setter_comment]
            pub fn #setter(&mut self, v: #return_t){
                self.0.insert(
                    #flag,
                    CertificationPathResultsTypes::#cpr_type(v),
                );
            }
        }
    };
    tokens.into()
}

/// SignatureWithDefault contains the results of parsing a cps_gets_and_sets_with_default definition, i.e., the
/// name of a value stored in a CertificationPathSettings map, the corresponding type and the default value.
struct SignatureWithDefault {
    value_name: ValueName,
    value_type: ValueType,
    default_value: DefaultValue,
}

/// Syntax contains the components of a cps_gets_and_sets_with_default, i.e., a value name, a comma and
/// a value type. For example:
/// ```text
/// cps_gets_and_sets_with_default!(PS_INITIAL_EXPLICIT_POLICY_INDICATOR, bool, false);
/// ```
struct SyntaxWithDefault {
    value_name: ValueName,
    _comma_token: Token!(,),
    value_type: ValueType,
    _comma_token2: Token!(,),
    default_value: DefaultValue,
}

impl Parse for SignatureWithDefault {
    fn parse(stream: ParseStream) -> Result<Self> {
        if stream.is_empty() {
            panic!("Write full function signature.");
        }

        let syntax = SyntaxWithDefault {
            value_name: stream.parse().unwrap(),
            _comma_token: stream.parse().unwrap(),
            value_type: stream.parse().unwrap(),
            _comma_token2: stream.parse().unwrap(),
            default_value: stream.parse().unwrap(),
        };

        Ok(SignatureWithDefault {
            value_name: syntax.value_name,
            value_type: syntax.value_type,
            default_value: syntax.default_value,
        })
    }
}

/// Generates a getter/setter pair on `CertificationPathSettings` whose getter always yields a value.
///
/// Takes a setting name, the type of the value it stores, and the value to return when the setting
/// has not been set. The getter returns `T` rather than `Option<T>`, answering the default both when
/// the key is absent and when it holds a different variant, so a caller reads a usable value without
/// restating the default at every call site.
///
/// ```text
/// cps_gets_and_sets_with_default!(PS_CHECK_REVOCATION_STATUS, bool, true);
/// ```
///
/// expands to:
///
/// ```text
/// impl CertificationPathSettings {
///     pub fn get_check_revocation_status(&self) -> bool { ... }   // `true` when unset
///     pub fn set_check_revocation_status(&mut self, v: bool) { ... }
/// }
/// ```
///
/// The default is an arbitrary expression rather than a literal, so a value needing construction can
/// be written inline. Note that a getter defined this way cannot report whether the value it
/// returned was stored or defaulted; where that distinction matters, use [`cps_gets_and_sets`].
#[proc_macro]
pub fn cps_gets_and_sets_with_default(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let signature = syn::parse_macro_input!(input as SignatureWithDefault);
    let flag = signature.value_name;
    let return_t = signature.value_type;
    let default_value = signature.default_value;

    let flag_str = format!("{flag}")[3..].to_lowercase();
    let getter_str = format!("get_{flag_str}");
    let setter_str = format!("set_{flag_str}");
    let cps_type_str = format!("{return_t}");
    let mut upper_cps_type_str = if is_string_numeric(&cps_type_str[1..]) {
        cps_type_str.to_uppercase()
    } else {
        cps_type_str
    };
    if upper_cps_type_str == "bool" {
        upper_cps_type_str = "Bool".to_string();
    }
    let getter = syn::Ident::new(&getter_str, flag.span());
    let setter = syn::Ident::new(&setter_str, flag.span());
    let cps_type = syn::Ident::new(&upper_cps_type_str, return_t.span());

    let getter_comment = format!(
        "`{getter_str}` is used to retrieve `{flag}` items from a [`CertificationPathSettings`] instance"
    );
    let setter_comment = format!(
        "`{setter_str}` is used to set `{flag}` items in a [`CertificationPathSettings`] instance"
    );

    let tokens = quote! {
        impl CertificationPathSettings {
            #[doc = #getter_comment]
            pub fn #getter(&self)->#return_t{
                if self.0.contains_key(#flag) {
                    return match self.0[#flag] {
                        CertificationPathProcessingTypes::#cps_type(v) => v.clone(),
                        _ => #default_value,
                    };
                }
                #default_value
            }
            #[doc = #setter_comment]
            pub fn #setter(&mut self, v: #return_t){
                self.0.insert(
                    #flag.to_string(),
                    CertificationPathProcessingTypes::#cps_type(v),
                );
            }
        }
    };
    tokens.into()
}

/// Generates a getter/setter pair on `CertificationPathResults` whose getter always yields a value.
///
/// The counterpart of [`cps_gets_and_sets_with_default`] for the results map.
///
/// ```text
/// cpr_gets_and_sets_with_default!(PR_PROCESSED_EXTENSIONS, ObjectIdentifierSet, BTreeSet::new());
/// ```
///
/// expands to:
///
/// ```text
/// impl CertificationPathResults {
///     pub fn get_processed_extensions(&self) -> ObjectIdentifierSet { ... }   // empty set when unset
///     pub fn set_processed_extensions(&mut self, v: ObjectIdentifierSet) { ... }
/// }
/// ```
#[proc_macro]
pub fn cpr_gets_and_sets_with_default(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let signature = syn::parse_macro_input!(input as SignatureWithDefault);
    let flag = signature.value_name;
    let return_t = signature.value_type;
    let default_value = signature.default_value;

    let flag_str = format!("{flag}")[3..].to_lowercase();
    let getter_str = format!("get_{flag_str}");
    let setter_str = format!("set_{flag_str}");
    let cpr_type_str = format!("{return_t}");
    let mut upper_cpr_type_str = if is_string_numeric(&cpr_type_str[1..]) {
        cpr_type_str.to_uppercase()
    } else {
        cpr_type_str
    };
    if upper_cpr_type_str == "bool" {
        upper_cpr_type_str = "Bool".to_string();
    }
    let getter = syn::Ident::new(&getter_str, flag.span());
    let setter = syn::Ident::new(&setter_str, flag.span());
    let cpr_type = syn::Ident::new(&upper_cpr_type_str, return_t.span());

    let getter_comment = format!(
        "`{getter_str}` is used to retrieve `{flag}` items from a [`CertificationPathResults`] instance"
    );
    let setter_comment = format!(
        "`{setter_str}` is used to set `{flag}` items in a [`CertificationPathResults`] instance"
    );

    let tokens = quote! {
        impl CertificationPathResults {
            #[doc = #getter_comment]
            pub fn #getter(&self)->#return_t{
                if self.0.contains_key(#flag) {
                    return match &self.0[#flag] {
                        CertificationPathResultsTypes::#cpr_type(v) => v.clone(),
                        _ => #default_value,
                    };
                }
                #default_value
            }
            #[doc = #setter_comment]
            pub fn #setter(&mut self, v: #return_t){
                self.0.insert(
                    #flag,
                    CertificationPathResultsTypes::#cpr_type(v),
                );
            }
        }
    };
    tokens.into()
}
