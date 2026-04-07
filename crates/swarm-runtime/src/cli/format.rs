pub fn print_json_or_text<T: serde::Serialize>(
    json_mode: bool,
    value: &T,
    text: &str,
) -> Result<(), serde_json::Error> {
    if json_mode {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        println!("{text}");
    }
    Ok(())
}
