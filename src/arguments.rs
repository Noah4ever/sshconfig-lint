/// Split OpenSSH configuration arguments using the rules from
/// `misc.c::argv_split`: spaces and tabs separate arguments, matching single
/// or double quotes group text, and a small set of backslash escapes is
/// recognised.
pub(crate) fn split_arguments(value: &str, terminate_on_comment: bool) -> Option<Vec<String>> {
    let characters = value.chars().collect::<Vec<_>>();
    let mut arguments = Vec::new();
    let mut index = 0;

    while index < characters.len() {
        while matches!(characters[index], ' ' | '\t') {
            index += 1;
            if index == characters.len() {
                return Some(arguments);
            }
        }
        if terminate_on_comment && characters[index] == '#' {
            break;
        }

        let mut argument = String::new();
        let mut quote = None;

        while index < characters.len() {
            let character = characters[index];
            if character == '\\' {
                let next = characters.get(index + 1).copied();
                if next.is_some_and(|next| {
                    matches!(next, '\'' | '"' | '\\') || (quote.is_none() && next == ' ')
                }) {
                    index += 1;
                    argument.push(characters[index]);
                } else {
                    argument.push(character);
                }
            } else if quote.is_none() && matches!(character, ' ' | '\t') {
                break;
            } else if quote.is_none() && matches!(character, '\'' | '"') {
                quote = Some(character);
            } else if quote == Some(character) {
                quote = None;
            } else {
                argument.push(character);
            }
            index += 1;
        }

        if quote.is_some() {
            return None;
        }
        arguments.push(argument);
    }

    Some(arguments)
}
