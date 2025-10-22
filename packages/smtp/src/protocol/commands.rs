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

impl Command {
	pub fn parse(input: &str) -> Result<Command, &'static str> {
		let mut parts = input.trim().split_whitespace();
		let command = parts.next().ok_or("Empty command")?.to_uppercase();

		match command.as_str() {
			"HELO" => {
				let domain = parts.next().ok_or("Missing domain for HELO")?;
				Ok(Command::Helo(domain.to_string()))
			}
			"EHLO" => {
				let domain = parts.next().ok_or("Missing domain for EHLO")?;
				Ok(Command::Ehlo(domain.to_string()))
			}
			"MAIL" => {
				let from = parts.next().ok_or("Missing from for MAIL")?;
				Ok(Command::Mail(from.to_string()))
			}
			"RCPT" => {
				let to = parts.next().ok_or("Missing to for RCPT")?;
				Ok(Command::Rcpt(to.to_string()))
			}
			"DATA" => Ok(Command::Data),
			"QUIT" => Ok(Command::Quit),
			"RSET" => Ok(Command::Rset),
			"NOOP" => Ok(Command::Noop),
			_ => Err("Unknown command"),
		}
	}
}
