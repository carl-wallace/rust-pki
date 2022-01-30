//! Procedural macros used in the definition and implementation of getters and setters for CertificationPathSettings

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
///     ```
///     cps_gets_and_sets!(PS_EXTENDED_KEY_USAGE, ObjectIdentifierSet);
///     ```
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

#[proc_macro]
pub fn cps_gets_and_sets(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let signature = syn::parse_macro_input!(input as Signature);
    let flag = signature.value_name;
    let return_t = signature.value_type;

    let flag_str = format!("{}", flag)[3..].to_lowercase();
    let getter_str = format!("get_{}", flag_str);
    let setter_str = format!("set_{}", flag_str);
    let cps_type_str = format!("{}", return_t);
    let mut upper_cps_type_str = if let true = is_string_numeric(&cps_type_str[1..]) {
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
        "`{}` is used to retrieve `{}` items from a [`CertificationPathSettings`] instance",
        getter_str, flag
    );
    let setter_comment = format!(
        "`{}` is used to set `{}` items in a [`CertificationPathSettings`] instance",
        setter_str, flag
    );

    let tokens = quote! {
            #[doc = #getter_comment]
            pub fn #getter(cps: &CertificationPathSettings)->Option<#return_t>{
                if cps.contains_key(#flag) {
                    return match &cps[#flag] {
                        CertificationPathProcessingTypes::#cps_type(v) => Some(v.clone()),
                        _ => None,
                    };
                }
                None
            }
            #[doc = #setter_comment]
            pub fn #setter(cps: &mut CertificationPathSettings, v: #return_t){
                cps.insert(
                    #flag,
                    CertificationPathProcessingTypes::#cps_type(v),
                );
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
///     ```
///     cps_gets_and_sets_with_default!(PS_INITIAL_EXPLICIT_POLICY_INDICATOR, bool, false);
///     ```
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

#[proc_macro]
pub fn cps_gets_and_sets_with_default(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let signature = syn::parse_macro_input!(input as SignatureWithDefault);
    let flag = signature.value_name;
    let return_t = signature.value_type;
    let default_value = signature.default_value;

    let flag_str = format!("{}", flag)[3..].to_lowercase();
    let getter_str = format!("get_{}", flag_str);
    let setter_str = format!("set_{}", flag_str);
    let cps_type_str = format!("{}", return_t);
    let mut upper_cps_type_str = if let true = is_string_numeric(&cps_type_str[1..]) {
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
        "`{}` is used to retrieve `{}` items from a [`CertificationPathSettings`] instance",
        getter_str, flag
    );
    let setter_comment = format!(
        "`{}` is used to set `{}` items in a [`CertificationPathSettings`] instance",
        setter_str, flag
    );

    let tokens = quote! {
            #[doc = #getter_comment]
            pub fn #getter(cps: &CertificationPathSettings)->#return_t{
                if cps.contains_key(#flag) {
                    return match &cps[#flag] {
                        CertificationPathProcessingTypes::#cps_type(v) => v.clone(),
                        _ => #default_value,
                    };
                }
                #default_value
            }
            #[doc = #setter_comment]
            pub fn #setter(cps: &mut CertificationPathSettings, v: #return_t){
                cps.insert(
                    #flag,
                    CertificationPathProcessingTypes::#cps_type(v),
                );
            }
    };
    tokens.into()
}
