use std::{error::Error, fmt};

#[derive(Debug, PartialEq)]
pub enum Command {
	Helo(String),
	Ehlo(String),
	Mail(String),
	Rcpt(String),
	Data,
	Quit,
	Rset,
	Noop,
}

#[derive(Debug)]
pub struct ParseError(pub &'static str);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl Error for ParseError {}

impl Command {
	pub fn parse(line: &str) -> Result<Self, ParseError> {
		let (verb, rest) = split_verb(line);
		match verb.as_str() {
			"HELO" => Ok(Command::Helo(rest.trim().to_string())),
			"EHLO" => Ok(Command::Ehlo(rest.trim().to_string())),
			"MAIL" => {
				let path = parse_path_arg(rest, "FROM")
					.map_err(|_| ParseError("MAIL expects FROM:<path>"))?;
				Ok(Command::Mail(path))
			}
			"RCPT" => {
				let path = parse_path_arg(rest, "TO")
					.map_err(|_| ParseError("RCPT expects TO:<path>"))?;
				Ok(Command::Rcpt(path))
			}
			"DATA" => Ok(Command::Data),
			"RSET" => Ok(Command::Rset),
			"NOOP" => Ok(Command::Noop),
			"QUIT" => Ok(Command::Quit),
			_ => Err(ParseError("Unrecognized command")),
		}
	}
}

fn split_verb(line: &str) -> (String, &str) {
	let mut it = line.splitn(2, char::is_whitespace);
	let verb = it.next().unwrap_or("").to_ascii_uppercase();
	let rest = it.next().unwrap_or("");
	(verb, rest)
}

/// Parse `PREFIX : <path> [ SP params ]`, case-insensitive for PREFIX.
/// Returns the path without angle brackets; `<>` becomes empty string.
fn parse_path_arg(rest: &str, expect_prefix: &str) -> Result<String, ()> {
	let mut s = rest.trim_start();

	// Case-insensitive match for e.g. "FROM:" or "FROM :"
	if !s.to_ascii_uppercase().starts_with(&(expect_prefix.to_ascii_uppercase() + ":")) {
		// Allow a space before the colon too, e.g. "FROM :"
		if !s.to_ascii_uppercase().starts_with(&(expect_prefix.to_ascii_uppercase() + " :")) {
			return Err(());
		}
	}

	// Skip past "FROM:" or "FROM :"
	if let Some(pos) = s.find(':') {
		s = &s[pos + 1..];
	}

	s = s.trim_start();

	// Expect <path> or <>
	if !s.starts_with('<') {
		return Err(());
	}

	let close = s.find('>').ok_or(())?;
	let path = &s[1..close];
	Ok(path.to_string())
}



fn take_token(s: &str) -> Option<(&str, &str)> {
	// token is up to first whitespace
	let s = s.trim_start();
	let idx = s.find(char::is_whitespace).unwrap_or(s.len());
	Some((&s[..idx], &s[idx..]))
}

fn eq_ci(a: &str, b: &str) -> bool {
	a.eq_ignore_ascii_case(b)
}
