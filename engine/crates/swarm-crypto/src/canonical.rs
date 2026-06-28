//! RFC 8785 JSON canonicalization.

use std::cmp::Ordering;

use serde_json::Value;

use crate::error::{Error, Result};

/// Canonicalize a JSON value using RFC 8785 (JCS).
pub fn canonicalize(value: &Value) -> Result<String> {
    match value {
        Value::Object(map) => {
            let mut pairs: Vec<_> = map.iter().collect();
            pairs.sort_by(|(a, _), (b, _)| cmp_utf16_code_units(a.as_str(), b.as_str()));

            let mut out = String::from("{");
            for (index, (key, value)) in pairs.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&escape_json_string(key));
                out.push_str("\":");
                out.push_str(&canonicalize(value)?);
            }
            out.push('}');
            Ok(out)
        }
        Value::Array(values) => {
            let mut out = String::from("[");
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&canonicalize(value)?);
            }
            out.push(']');
            Ok(out)
        }
        Value::String(value) => Ok(format!("\"{}\"", escape_json_string(value))),
        Value::Number(value) => canonicalize_number(value),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Null => Ok("null".to_string()),
    }
}

fn cmp_utf16_code_units(left: &str, right: &str) -> Ordering {
    let mut left_units = left.encode_utf16();
    let mut right_units = right.encode_utf16();

    loop {
        match (left_units.next(), right_units.next()) {
            (Some(left), Some(right)) => match left.cmp(&right) {
                Ordering::Equal => {}
                non_eq => return non_eq,
            },
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

fn canonicalize_number(number: &serde_json::Number) -> Result<String> {
    if let Some(value) = number.as_i64() {
        return Ok(value.to_string());
    }
    if let Some(value) = number.as_u64() {
        return Ok(value.to_string());
    }
    if let Some(value) = number.as_f64() {
        return canonicalize_f64(value);
    }
    Err(Error::JsonError("Unsupported JSON number".into()))
}

fn canonicalize_f64(value: f64) -> Result<String> {
    if !value.is_finite() {
        return Err(Error::JsonError(
            "Non-finite numbers are not valid JSON".into(),
        ));
    }
    if value == 0.0 {
        return Ok("0".to_string());
    }

    let sign = if value.is_sign_negative() { "-" } else { "" };
    let abs = value.abs();
    let use_exponential = !(1e-6..1e21).contains(&abs);

    let mut buffer = ryu::Buffer::new();
    let rendered = buffer.format_finite(abs);
    let (digits, sci_exp) = parse_to_scientific_parts(rendered)?;

    if !use_exponential {
        let rendered = render_decimal(&digits, sci_exp);
        return Ok(format!("{sign}{rendered}"));
    }

    let mantissa = if digits.len() == 1 {
        digits.clone()
    } else {
        format!("{}.{}", &digits[0..1], &digits[1..])
    };
    let exp_sign = if sci_exp >= 0 { "+" } else { "" };
    Ok(format!("{sign}{mantissa}e{exp_sign}{sci_exp}"))
}

fn parse_to_scientific_parts(rendered: &str) -> Result<(String, i32)> {
    let rendered = rendered.trim();
    if rendered.is_empty() {
        return Err(Error::JsonError("Empty number string".into()));
    }

    let (mantissa, exp_opt) = if let Some((mantissa, exponent)) = rendered.split_once('e') {
        (mantissa, Some(exponent))
    } else if let Some((mantissa, exponent)) = rendered.split_once('E') {
        (mantissa, Some(exponent))
    } else {
        (rendered, None)
    };

    let (digits_before_dot, mut digits) = if let Some((left, right)) = mantissa.split_once('.') {
        let fraction = right.trim_end_matches('0');
        (left.len() as i32, format!("{left}{fraction}"))
    } else {
        (mantissa.len() as i32, mantissa.to_string())
    };

    digits = digits.trim_start_matches('0').to_string();
    if digits.is_empty() {
        digits = "0".to_string();
    }
    digits = digits.trim_end_matches('0').to_string();
    if digits.is_empty() {
        digits = "0".to_string();
    }

    let sci_exp = if let Some(exp_str) = exp_opt {
        let exp: i32 = exp_str
            .parse()
            .map_err(|_| Error::JsonError(format!("Invalid exponent: {exp_str}")))?;
        exp + (digits_before_dot - 1)
    } else if mantissa.contains('.') {
        let (int_part, frac_part_raw) = mantissa
            .split_once('.')
            .ok_or_else(|| Error::JsonError("Invalid decimal".into()))?;
        let frac_part = frac_part_raw.trim_end_matches('0');

        let int_stripped = int_part.trim_start_matches('0');
        if !int_stripped.is_empty() {
            (int_stripped.len() as i32) - 1
        } else {
            let leading_zeros = frac_part.chars().take_while(|ch| *ch == '0').count() as i32;
            -(leading_zeros + 1)
        }
    } else {
        (mantissa.trim_start_matches('0').len() as i32) - 1
    };

    Ok((digits, sci_exp))
}

fn render_decimal(digits: &str, sci_exp: i32) -> String {
    let digits_len = digits.len() as i32;
    let shift = sci_exp - (digits_len - 1);

    if shift >= 0 {
        let mut out = String::with_capacity(digits.len() + shift as usize);
        out.push_str(digits);
        out.extend(std::iter::repeat_n('0', shift as usize));
        return out;
    }

    let pos = digits_len + shift;
    if pos > 0 {
        let pos_usize = pos as usize;
        let mut out = String::with_capacity(digits.len() + 1);
        out.push_str(&digits[..pos_usize]);
        out.push('.');
        out.push_str(&digits[pos_usize..]);
        trim_decimal(out)
    } else {
        let zeros = (-pos) as usize;
        let mut out = String::with_capacity(2 + zeros + digits.len());
        out.push_str("0.");
        out.extend(std::iter::repeat_n('0', zeros));
        out.push_str(digits);
        trim_decimal(out)
    }
}

fn trim_decimal(mut rendered: String) -> String {
    if let Some(dot) = rendered.find('.') {
        while rendered.ends_with('0') {
            rendered.pop();
        }
        if rendered.len() == dot + 1 {
            rendered.pop();
        }
    }
    rendered
}

fn escape_json_string(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\u{08}' => result.push_str("\\b"),
            '\u{0C}' => result.push_str("\\f"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            control if control.is_control() => {
                result.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => result.push(other),
        }
    }
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn jcs_vector_b_numbers() {
        let value = serde_json::json!({
            "a": 1.0,
            "b": 0.0,
            "c": -0.0,
            "d": 1e21,
            "e": 1e20,
            "f": 1e-6,
            "g": 1e-7,
        });

        let canonical = canonicalize(&value).unwrap();
        assert_eq!(
            canonical,
            r#"{"a":1,"b":0,"c":0,"d":1e+21,"e":100000000000000000000,"f":0.000001,"g":1e-7}"#
        );
    }

    #[test]
    fn jcs_vector_a_unicode_and_controls() {
        let value = serde_json::json!({
            "s": "e",
            "u2028": "\u{2028}",
            "u2029": "\u{2029}",
            "emoji": "X",
            "nl": "\n",
            "tab": "\t",
        });

        let canonical = canonicalize(&value).unwrap();
        assert_eq!(
            canonical,
            format!(
                r#"{{"emoji":"X","nl":"\n","s":"e","tab":"\t","u2028":"{}","u2029":"{}"}}"#,
                "\u{2028}", "\u{2029}"
            )
        );
    }

    #[test]
    fn jcs_vector_c_escape_shortcuts() {
        let value = serde_json::json!({
            "b": "\u{0008}",
            "f": "\u{000c}",
            "ctl": "\u{000f}",
            "quote": "\"",
            "backslash": "\\",
        });

        let canonical = canonicalize(&value).unwrap();
        assert_eq!(
            canonical,
            r#"{"b":"\b","backslash":"\\","ctl":"\u000f","f":"\f","quote":"\""}"#
        );
    }

    #[test]
    fn jcs_vector_d_numeric_string_keys() {
        let value = serde_json::json!({
            "2": "b",
            "10": "a",
            "a": 0,
        });

        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, r#"{"10":"a","2":"b","a":0}"#);
    }

    #[test]
    fn sorted_keys() {
        let value = serde_json::json!({
            "z": 1,
            "a": 2,
            "m": 3,
        });

        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn sorted_keys_use_utf16_code_units() {
        let value = serde_json::json!({
            "\u{e000}": 1,
            "𐐷": 2,
        });

        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, "{\"𐐷\":2,\"\u{e000}\":1}");
    }

    #[test]
    fn nested_objects() {
        let value = serde_json::json!({
            "outer": {
                "inner": "value"
            }
        });

        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, r#"{"outer":{"inner":"value"}}"#);
    }

    #[test]
    fn arrays() {
        let value = serde_json::json!([1, 2, 3]);
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, "[1,2,3]");
    }
}
