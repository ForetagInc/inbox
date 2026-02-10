#[derive(Default, Debug)]
pub struct Transaction {
	pub mail_from: Option<String>,
	pub rcpt_to: Vec<String>,
	pub data: Option<Vec<u8>>,
}
