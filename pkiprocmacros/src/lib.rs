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
                    #flag.to_string(),
                    CertificationPathProcessingTypes::#cps_type(v),
                );
            }
    };
    tokens.into()
}

#[proc_macro]
pub fn cpr_gets_and_sets(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let signature = syn::parse_macro_input!(input as Signature);
    let flag = signature.value_name;
    let return_t = signature.value_type;

    let flag_str = format!("{}", flag)[3..].to_lowercase();
    let getter_str = format!("get_{}", flag_str);
    let setter_str = format!("set_{}", flag_str);
    let cpr_type_str = format!("{}", return_t);
    let mut upper_cpr_type_str = if let true = is_string_numeric(&cpr_type_str[1..]) {
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
        "`{}` is used to retrieve `{}` items from a [`CertificationPathResults`] instance",
        getter_str, flag
    );
    let setter_comment = format!(
        "`{}` is used to set `{}` items in a [`CertificationPathResults`] instance",
        setter_str, flag
    );

    let tokens = quote! {
            #[doc = #getter_comment]
            pub fn #getter(cpr: &CertificationPathResults)->Option<#return_t>{
                if cpr.contains_key(#flag) {
                    return match &cpr[#flag] {
                        CertificationPathResultsTypes::#cpr_type(v) => Some(v.clone()),
                        _ => None,
                    };
                }
                None
            }
            #[doc = #setter_comment]
            pub fn #setter(cpr: &mut CertificationPathResults, v: #return_t){
                cpr.insert(
                    #flag,
                    CertificationPathResultsTypes::#cpr_type(v),
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
                    #flag.to_string(),
                    CertificationPathProcessingTypes::#cps_type(v),
                );
            }
    };
    tokens.into()
}

#[proc_macro]
pub fn cpr_gets_and_sets_with_default(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let signature = syn::parse_macro_input!(input as SignatureWithDefault);
    let flag = signature.value_name;
    let return_t = signature.value_type;
    let default_value = signature.default_value;

    let flag_str = format!("{}", flag)[3..].to_lowercase();
    let getter_str = format!("get_{}", flag_str);
    let setter_str = format!("set_{}", flag_str);
    let cpr_type_str = format!("{}", return_t);
    let mut upper_cpr_type_str = if let true = is_string_numeric(&cpr_type_str[1..]) {
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
        "`{}` is used to retrieve `{}` items from a [`CertificationPathSettings`] instance",
        getter_str, flag
    );
    let setter_comment = format!(
        "`{}` is used to set `{}` items in a [`CertificationPathSettings`] instance",
        setter_str, flag
    );

    let tokens = quote! {
            #[doc = #getter_comment]
            pub fn #getter(cpr: &CertificationPathResults)->#return_t{
                if cpr.contains_key(#flag) {
                    return match &cpr[#flag] {
                        CertificationPathResultsTypes::#cpr_type(v) => v.clone(),
                        _ => #default_value,
                    };
                }
                #default_value
            }
            #[doc = #setter_comment]
            pub fn #setter(cpr: &mut CertificationPathResults, v: #return_t){
                cpr.insert(
                    #flag,
                    CertificationPathResultsTypes::#cpr_type(v),
                );
            }
    };
    tokens.into()
}

struct Setting {
    setting_name: ValueName,
    cps: Ident,
    cx: Ident,
}

struct SyntaxSetting {
    setting_name: ValueName,
    _comma_token: Token!(,),
    cps: Ident,
    _comma_token2: Token!(,),
    cx: Ident,
}

impl Parse for Setting {
    fn parse(stream: ParseStream) -> Result<Self> {
        if stream.is_empty() {
            panic!("Write full function signature.");
        }

        let syntax = SyntaxSetting {
            setting_name: stream.parse().unwrap(),
            _comma_token: stream.parse().unwrap(),
            cps: stream.parse().unwrap(),
            _comma_token2: stream.parse().unwrap(),
            cx: stream.parse().unwrap(),
        };

        Ok(Setting {
            setting_name: syntax.setting_name,
            cps: syntax.cps,
            cx: syntax.cx,
        })
    }
}

#[proc_macro]
pub fn setting_vars(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let setting = syn::parse_macro_input!(input as Setting);
    let setting_name = setting.setting_name;
    let cps = setting.cps;
    let cx = setting.cx;
    let getter_str = format!("get_{}", setting_name);
    let getter = syn::Ident::new(&getter_str, setting_name.span());
    let state_str = format!("s_{}", setting_name);
    let state = syn::Ident::new(&state_str, setting_name.span());

    let tokens = quote! {
        let #setting_name = #getter(&#cps);
        let #state = use_state(#cx, || #setting_name);
    };
    tokens.into()
}

// todo remove this or figure out if it can work
// struct SettingRow {
//     setting_name: Ident,
//     setting_type: Ident,
// }
//
// struct SyntaxSettingRow {
//     setting_name: Ident,
//     _comma_token: Token!(,),
//     setting_type: Ident,
// }
//
// impl Parse for SettingRow {
//     fn parse(stream: ParseStream) -> Result<Self> {
//         if stream.is_empty() {
//             panic!("Write full function signature.");
//         }
//
//         let syntax = SyntaxSettingRow {
//             setting_name: stream.parse().unwrap(),
//             _comma_token: stream.parse().unwrap(),
//             setting_type: stream.parse().unwrap(),
//         };
//
//         Ok(SettingRow {
//             setting_name: syntax.setting_name,
//             setting_type: syntax.setting_type,
//         })
//     }
// }
//
// #[proc_macro]
// pub fn setting_row(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
//     // let setting = syn::parse_macro_input!(input as SettingRow);
//     // let setting_name = setting.setting_name;
//     // let setting_type = setting.setting_type;
//     // let state_str = format!("s_{}", setting_name);
//     // let state = syn::Ident::new(&state_str, setting_name.span());
//     //
//     let tokens = quote! {
//         // tr{
//         //     td{label {r#for: "#setting_name", "Placeholder: "}}
//         //     td{input { r#type: "#setting_type", name: "#setting_name", checked: "{#state}", value: "{#state}" }}
//         // }
//     };
//     tokens.into()
// }
