pub(super) fn parse_value_arguments(value: &str) -> Option<Vec<String>> {
    crate::arguments::split_arguments(value, false)
}

#[cfg(test)]
mod tests {
    use super::parse_value_arguments;

    #[test]
    fn matches_openssh_argument_splitting_examples() {
        let cases = [
            ("", vec![]),
            ("    ", vec![]),
            ("smiley leamas", vec!["smiley", "leamas"]),
            (r#"leamas " smiley ""#, vec!["leamas", " smiley "]),
            (r#"smiley" leamas" liz"#, vec!["smiley leamas", "liz"]),
            (r#"\"smiley\'"#, vec![r#""smiley'"#]),
            (r#"smiley\'s leamas\'"#, vec!["smiley's", "leamas'"]),
            (r#"leamas\\smiley"#, vec![r#"leamas\smiley"#]),
            (r#"smiley\ leamas"#, vec!["smiley leamas"]),
            (r#"'smiley\ leamas'"#, vec![r#"smiley\ leamas"#]),
        ];

        for (input, expected) in cases {
            assert_eq!(
                parse_value_arguments(input),
                Some(expected.into_iter().map(str::to_string).collect()),
                "{input:?}"
            );
        }
    }

    #[test]
    fn preserves_empty_quoted_arguments_and_rejects_unbalanced_quotes() {
        assert_eq!(parse_value_arguments(r#""""#), Some(vec![String::new()]));
        assert_eq!(parse_value_arguments("''"), Some(vec![String::new()]));
        assert_eq!(parse_value_arguments(r#""unterminated"#), None);
        assert_eq!(parse_value_arguments("'unterminated"), None);
    }
}
