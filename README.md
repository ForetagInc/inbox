# Inbox

## Features

- Complete Mail Server: MTA, MDA, MSA etc.
- Calendar Sync via CalDav
- Contacts Sync via CardDav
- Transactional Email API via GraphQL

## Architecture

- HTTP Server (GraphQL API + WebDav / CalDav / CardDav etc.)
- SMTP Server (25) - Mail Transfer (Incoming)
- SMTP Server (587) - Mail Submission (Outgoing)
- IMAP Server

## SMTP Configuration

The server now loads SMTP and mail-auth configuration from environment variables:

```env
SERVER_HOSTNAME=mail.example.com
SERVER_BIND_ADDR=0.0.0.0

SMTP_TRANSFER_PORT=25
SMTP_SUBMISSION_PORT=587

SMTP_OUTBOUND_PORT=25
SMTP_OUTBOUND_REQUIRE_STARTTLS=false
SMTP_OUTBOUND_ALLOW_INVALID_CERTS=false
SMTP_OUTBOUND_ALLOW_PLAINTEXT_FALLBACK=true
SMTP_OUTBOUND_TIMEOUT_SECS=30

SMTP_REQUIRE_SPF_PASS=true
SMTP_REQUIRE_DKIM_PASS=false
SMTP_REQUIRE_DMARC_PASS=false
SMTP_AUTH_ALLOW_HEADER_OVERRIDE=false

# Optional DKIM signing for outbound submission (PKCS8 RSA private key in base64)
SMTP_DKIM_DOMAIN=example.com
SMTP_DKIM_SELECTOR=mail
SMTP_DKIM_PRIVATE_KEY_B64_PKCS8=
SMTP_DKIM_HEADERS=From,To,Subject,Date
```

## SMTP Behavior

- Port `25` (transfer): accepts incoming SMTP mail, verifies SPF/DKIM/DMARC, applies policy from `SMTP_REQUIRE_*`, and stores accepted RFC822 messages under `data/incoming/`.
- Port `587` (submission): accepts SMTP submissions and sends directly to remote destination SMTP servers (MX lookup by recipient domain, with A/AAAA fallback), with optional DKIM signing if configured.
- Multi-tenant: per-domain DKIM and auth policy are resolved from SurrealDB table `has_domain` (`IN organization`, `OUT domain`) with optional override fields on the edge.

## GraphQL Send API

`send_email` now performs real SMTP delivery:

```graphql
mutation Send {
  sendEmail(
    from: "sender@example.com"
    to: ["user@example.net"]
    subject: "Hello"
    textBody: "Hi from Inbox"
    htmlBody: "<p>Hi from Inbox</p>"
  )
}
```
