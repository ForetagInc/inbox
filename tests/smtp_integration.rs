use std::{
	io,
	net::{IpAddr, Ipv4Addr},
	path::Path,
	pin::Pin,
	task::{Context, Poll}
};

use inbox::{
	config::{
		Config, DkimConfig, MailAuthConfig, OutboundConfig, ServerConfig, SmtpConfig
	},
	protocols::smtp::{
		commands::Command,
		handler::{self, DeliveryMode, outgoing::OutgoingRequest},
		state::{SessionState, SmtpSession}
	}
};
use tokio::{
	io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
	net::TcpListener,
	sync::oneshot
};

const TEST_DKIM_PKCS8_B64: &str = "MIIEogIBAAKCAQEAzCURu2qY2PLkq7+ANw735E6VJ06zhQVd0os2Tr5fMzdMsiFQZOTXjoYcMxymNjWa4t4+vwXiW4RQ+6UG4GdRChPHAIDm95nwOGUXm/q6k/csJN9NHdvcR3zadZUgZE7dD0RKjqWVwJT2/oglfq5TH9EVYjJfcsooupKi9Zn+70izaFNQkPgcq/UBgivBL9DGUDvM+pA3lViENHkqenTl9GvBfwXuKcB6e+N+iNSVU9OOoTkz59xJoFoUK/D1AT/270y3fDX3sw/vBb4UFS6aFfhfudau1JVGsGaLjOoYmJnvRU2vTZzeycLzY9qdYgat49VL3YGGleZt76Gns7RygQIDAQABAoIBAGEq+8ezM1GAO2usWQDb9Q4MgV4WTchxB3lhndXZM0MTfUQEK1n6uscx+lYxusNuvGxj0IXn7RgWYN2GbUF+q8oaI8yPjmAoO3j8VUJ/EzO+oJpkVzZxIeY8/VaeRq64AuxzWvGOyzrBLNd2QjKMEzC/umflBh2DL+OuTDaOuBN4MnFjliheVLcUByZHWdGXaLF78OHZ4QiWeG4sQ3A13W4eNpJJa7e0fuIqUPzrxstAZnt+Rq90+B01ElS0HWxH4fadZUS6F3cFoI2PyIfq1iK+0i5MclIuE1+A94T8VWfZz5BWRgV9Ximgz08p8Jp6OueeXF5gASxcq4b1WB8YQ2kCgYEA/ZBD3zU0ungEX1H5h89PC3+blXFO5EikG0PqHcd+Jgr1ia5Jf7e5tp7K9Z10BTJVm1rOBaeHcPSudxryFfHr3+TJHoBcWoQjOo1FnqMYvfhTyuLldwJ36UghHzAOmJ1c63hubKL0W9yUVd90AjZcSHexoLnkLN0yKBgohDMWYa8CgYEAzhs9fHRMGTNs0MiOy4Onem8oZWFp4CwQATwFn4/552tPrHYeH8ASCUl2uNHuHVfouMMa6ujEyhPekIdEWSfwGPUVWYMaEWGRRPK3AnB3NRR1vw/odvEM/OqTERaPWtpNlK4lxP23Eq7za7xLbWxHQ6UVX15niNuZs05IYcmnas8CgYBhl40H8+p/eoH0ThDEfL3npw2yzxGWO38uH02UeJvM+JrYiwQu6//Gkgd70UY+WckpKiHxezFeAE7F+NEEMUCfw+bEnpLtI76LYqRREmULePCHPh0jWQfd+a0F2/FCPA7vckLN/UofsR5GjuKPl2ydV7Q+ME3qFpifZezyNNeAcQKBgBH9Hqi2Hc41RtISLyRkIUH2Ybg3gF4oel0hN/xtPIqOOy36QTbUNL7Kwqnu6LF28sDthnPqTQK2KT7ED5sYeUQ0X+CoKKZLtbom1QJJfp4LYxuB7/AxqciJULy1E14Cn7LSYEmJO2lOC8DjdlHemXm19t+UBcVUJV4Y/whJ6WrRAoGAK/vkD4ewCN0MLeOhskAkXalc6c9rqotAiQSe10wViy4sqUuRkfqB7xcHATD9NOcLeAWa7UrZnbu14BaYRFrGlYQyA5qNjBxsOzMX4k1V2XkGBggieTeSuW/833o3ewNu1P5XjZ9zfTbMA26++kdPBbHksfqENMGhvTUiGkbEZoY=";

#[derive(Default)]
struct CaptureWriter {
	buf: Vec<u8>,
}

impl AsyncWrite for CaptureWriter {
	fn poll_write(
		mut self: Pin<&mut Self>,
		_: &mut Context<'_>,
		data: &[u8],
	) -> Poll<io::Result<usize>> {
		self.buf.extend_from_slice(data);
		Poll::Ready(Ok(data.len()))
	}

	fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
		Poll::Ready(Ok(()))
	}

	fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
		Poll::Ready(Ok(()))
	}
}

#[tokio::test]
async fn inbound_transfer_accepts_authenticated_mail() {
	let temp_incoming_dir = std::env::temp_dir().join(format!(
		"inbox_smtp_test_{}",
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.expect("clock")
			.as_millis()
	));
	unsafe {
		std::env::set_var("INBOX_INCOMING_DIR", &temp_incoming_dir);
	}

	let config = test_config(2525, 2587);
	let mut session = SmtpSession::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
	session.state = SessionState::Ready;

	let mut sink_reader = empty_reader().await;
	let mut writer = CaptureWriter::default();
	handler::handle_command(
		Command::Ehlo("mx.sender.test".into()),
		&mut session,
		DeliveryMode::Transfer,
		&config,
		&mut sink_reader,
		&mut writer,
	)
	.await
	.expect("ehlo should succeed");

	let mut sink_reader = empty_reader().await;
	let mut writer = CaptureWriter::default();
	handler::handle_command(
		Command::Mail("alice@sender.test".into()),
		&mut session,
		DeliveryMode::Transfer,
		&config,
		&mut sink_reader,
		&mut writer,
	)
	.await
	.expect("mail from should succeed");

	let mut sink_reader = empty_reader().await;
	let mut writer = CaptureWriter::default();
	handler::handle_command(
		Command::Rcpt("bob@receiver.test".into()),
		&mut session,
		DeliveryMode::Transfer,
		&config,
		&mut sink_reader,
		&mut writer,
	)
	.await
	.expect("rcpt to should succeed");

	let incoming_data = concat!(
		"From: Alice <alice@sender.test>\r\n",
		"To: Bob <bob@receiver.test>\r\n",
		"Subject: Integration Test\r\n",
		"Message-ID: <smtp-integration@example.test>\r\n",
		"X-Inbox-Test-Auth: spf=pass;dkim=pass;dmarc=pass\r\n",
		"\r\n",
		"Hello over SMTP.\r\n",
		".\r\n"
	);
	let mut data_reader = reader_from(incoming_data.as_bytes()).await;
	let mut writer = CaptureWriter::default();
	handler::handle_command(
		Command::Data,
		&mut session,
		DeliveryMode::Transfer,
		&config,
		&mut data_reader,
		&mut writer,
	)
	.await
	.expect("data should succeed");

	let response = String::from_utf8(writer.buf).expect("valid utf8 response");
	assert!(response.contains("250 2.0.0 OK: received"));
	assert!(Path::new(&temp_incoming_dir).exists());

	unsafe {
		std::env::remove_var("INBOX_INCOMING_DIR");
	}
	let _ = tokio::fs::remove_dir_all(&temp_incoming_dir).await;
}

#[tokio::test]
async fn outbound_submission_sends_and_signs_dkim() {
	let listener = TcpListener::bind("127.0.0.1:0")
		.await
		.expect("listener should bind");
	let port = listener.local_addr().expect("local addr").port();

	let (tx, rx) = oneshot::channel::<Vec<u8>>();
	tokio::spawn(async move {
		let mut captured_message: Option<Vec<u8>> = None;
		for _ in 0..2 {
			let (socket, _) = listener.accept().await.expect("accept");
			let (reader, mut writer) = socket.into_split();
			let mut reader = BufReader::new(reader);
			let mut line = String::new();

			writer
				.write_all(b"220 test.local ESMTP\r\n")
				.await
				.expect("write greeting");

			loop {
				line.clear();
				let n = reader.read_line(&mut line).await.expect("read line");
				if n == 0 {
					break;
				}

				let upper = line.to_ascii_uppercase();
				if upper.starts_with("EHLO") {
					writer
						.write_all(b"250-test.local\r\n250 PIPELINING\r\n")
						.await
						.expect("write ehlo");
				} else if upper.starts_with("MAIL FROM:") || upper.starts_with("RCPT TO:") {
					writer.write_all(b"250 OK\r\n").await.expect("write ok");
				} else if upper.starts_with("DATA") {
					writer
						.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
						.await
						.expect("write data prompt");
					let mut data = Vec::new();
					loop {
						let mut bytes = Vec::new();
						let read = reader.read_until(b'\n', &mut bytes).await.expect("read data");
						if read == 0 {
							break;
						}
						if bytes == b".\r\n" {
							break;
						}
						data.extend_from_slice(&bytes);
					}
					captured_message = Some(data);
					writer
						.write_all(b"250 2.0.0 queued\r\n")
						.await
						.expect("write queued");
				} else if upper.starts_with("QUIT") {
					writer.write_all(b"221 Bye\r\n").await.expect("write quit");
					break;
				} else {
					writer
						.write_all(b"250 OK\r\n")
						.await
						.expect("write default");
				}
			}

			if captured_message.is_some() {
				break;
			}
		}

		tx.send(captured_message.unwrap_or_default())
			.expect("send captured message");
	});

	let config = test_config(port, 2587);
	let request = OutgoingRequest {
		from: "mailer@sender.test".into(),
		to: vec!["user@127.0.0.1".into()],
		subject: "Outbound Integration".into(),
		text_body: Some("Hello recipient".into()),
		html_body: None,
	};

	inbox::protocols::smtp::handler::outgoing::send_outgoing(request, &config)
		.await
		.expect("outgoing send should succeed");

	let raw_message = rx.await.expect("captured message available");
	let text = String::from_utf8(raw_message).expect("captured message must be utf8");
	assert!(text.contains("DKIM-Signature:"));
	assert!(text.contains("Subject: Outbound Integration"));
}

fn test_config(outbound_port: u16, submission_port: u16) -> Config {
	Config {
		server: ServerConfig {
			hostname: "mail.sender.test".to_string(),
			bind_addr: "127.0.0.1".to_string(),
			max_connections: 32,
		},
		smtp: SmtpConfig {
			transfer_port: 2525,
			submission_port,
			outbound: OutboundConfig {
				default_port: outbound_port,
				require_starttls: false,
				allow_invalid_certs: true,
				allow_plaintext_fallback: true,
				timeout: std::time::Duration::from_secs(5),
				dkim: Some(DkimConfig {
					domain: "sender.test".into(),
					selector: "mail".into(),
					private_key_b64_pkcs8: TEST_DKIM_PKCS8_B64.into(),
					headers: vec![
						"From".into(),
						"To".into(),
						"Subject".into(),
						"Date".into()
					],
				}),
			},
		},
		auth: MailAuthConfig {
			require_spf_pass: true,
			require_dkim_pass: true,
			require_dmarc_pass: true,
			allow_header_override: true,
		},
	}
}

async fn empty_reader() -> impl AsyncBufRead + Unpin {
	reader_from(b"").await
}

async fn reader_from(data: &[u8]) -> impl AsyncBufRead + Unpin {
	let (mut writer, reader) = tokio::io::duplex(16 * 1024);
	if !data.is_empty() {
		writer.write_all(data).await.expect("write test data");
	}
	writer.shutdown().await.expect("shutdown test writer");
	BufReader::new(reader)
}
