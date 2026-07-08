pub fn clean_name(s: &str) -> String {
    s.replace("(", "")
        .replace(")", "")
        .replace(";", "")
        .replace("{", "")
        .replace("}", "")
        .trim()
        .to_string()
}
