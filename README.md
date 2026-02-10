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
SMTP_OUTBOUND_TLS_MODE=required
SMTP_OUTBOUND_DANE_MODE=prefer
SMTP_OUTBOUND_DNSSEC_VALIDATE=true
SMTP_OUTBOUND_MTA_STS_ENFORCE=true
SMTP_TLS_REPORT_DIR=data/tlsrpt
SMTP_OUTBOUND_TIMEOUT_SECS=30
SMTP_OUTBOUND_QUEUE_ENABLED=true
SMTP_OUTBOUND_QUEUE_POLL_INTERVAL_SECS=2
SMTP_OUTBOUND_QUEUE_CLEANUP_INTERVAL_SECS=300
SMTP_OUTBOUND_QUEUE_BATCH_SIZE=100
SMTP_OUTBOUND_QUEUE_LEASE_SECS=120
SMTP_OUTBOUND_RETRY_BASE_DELAY_SECS=30
SMTP_OUTBOUND_RETRY_MAX_DELAY_SECS=3600
SMTP_OUTBOUND_MAX_ATTEMPTS=10
SMTP_OUTBOUND_TTL_SECS=86400
SMTP_OUTBOUND_DEAD_JOB_RETENTION_SECS=604800
SMTP_OUTBOUND_DELIVERY_RETENTION_SECS=2592000

SMTP_INBOUND_MAX_RCPT_TO=100
SMTP_MAX_MESSAGE_BYTES=26214400
SMTP_RATE_LIMIT_ENABLED=true
SMTP_RATE_LIMIT_WINDOW_SECS=60
SMTP_RATE_LIMIT_TRANSFER_CONNECTIONS_PER_WINDOW=240
SMTP_RATE_LIMIT_SUBMISSION_CONNECTIONS_PER_WINDOW=120
SMTP_RATE_LIMIT_TRANSFER_MESSAGES_PER_WINDOW=240
SMTP_RATE_LIMIT_SUBMISSION_MESSAGES_PER_WINDOW=120
SMTP_RATE_LIMIT_FAIL_OPEN_ON_DB_ERROR=true

SMTP_REQUIRE_SPF_PASS=true
SMTP_REQUIRE_DKIM_PASS=false
SMTP_REQUIRE_DMARC_PASS=false
SMTP_AUTH_ALLOW_HEADER_OVERRIDE=false

# Optional DKIM signing for outbound submission (PKCS8 RSA private key in base64)
SMTP_DKIM_DOMAIN=example.com
SMTP_DKIM_SELECTOR=mail
SMTP_DKIM_PRIVATE_KEY_B64_PKCS8=
SMTP_DKIM_HEADERS=From,To,Subject,Date

# Optional S3-compatible object storage (Cloudflare R2 via S3 API)
S3_ENDPOINT=https://<accountid>.r2.cloudflarestorage.com
S3_REGION=auto
S3_BUCKET=inbox-mail
S3_ACCESS_KEY_ID=
S3_SECRET_ACCESS_KEY=
S3_FORCE_PATH_STYLE=false

# Optional parsed body-part blob uploads for Standard tenants
INBOX_STORE_PARSED_PARTS=false

OTEL_ENABLED=false
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318/v1/traces
OTEL_SERVICE_NAME=inbox
OTEL_SAMPLE_RATIO=1.0
OTEL_CONSOLE_LOGS=true
```

## SMTP Behavior

- Port `25` (transfer): accepts incoming SMTP mail, verifies SPF/DKIM/DMARC, applies policy from `SMTP_REQUIRE_*`, and stores accepted RFC822 messages in S3-compatible storage when `S3_*` vars are set.
- Object key layout:
  - raw source (encrypted): `msg/{org}/{mailbox}/{message_id}.eml`
  - attachments (encrypted): `att/{org}/{mailbox}/{message_id}/{part_id}`
  - optional parsed body parts (encrypted): `part/{org}/{mailbox}/{message_id}/{mime_path}`
- Without `S3_*` config, inbox stores the same key hierarchy under local `INBOX_INCOMING_DIR` (default `data/incoming`).
- Port `587` (submission): accepts SMTP submissions and queues outbound jobs in DB (`outbound_queue`), then worker delivery claims jobs with DB leases (`queued -> processing`) for distributed-safe execution across instances.
- Outbound hard limits (fixed, non-configurable): message size `25 MB` (full RFC822 payload) and attachment payload `18 MB` per part.
- Queue leasing controls:
  - `SMTP_OUTBOUND_QUEUE_BATCH_SIZE`
  - `SMTP_OUTBOUND_QUEUE_LEASE_SECS`
- Queue retries and expiry:
  - exponential backoff (`SMTP_OUTBOUND_RETRY_*`)
  - max attempts (`SMTP_OUTBOUND_MAX_ATTEMPTS`)
  - TTL (`SMTP_OUTBOUND_TTL_SECS`)
- Queue cleanup controls:
  - `SMTP_OUTBOUND_QUEUE_CLEANUP_INTERVAL_SECS`
  - `SMTP_OUTBOUND_DEAD_JOB_RETENTION_SECS`
  - `SMTP_OUTBOUND_DELIVERY_RETENTION_SECS`
- SMTP rate limiting is configurable by env (`SMTP_RATE_LIMIT_*`) and enforced per source IP for connection and message acceptance using DB-backed window buckets (distributed-safe across instances).
- Multi-tenant: per-domain DKIM and auth policy are resolved from SurrealDB table `has_domain` (`IN organization`, `OUT domain`) with optional override fields on the edge.
- Tenant encryption options on `has_domain`:
  - `enc_mode`: `standard` or `e2ee`
  - `enc_sse_c_key_b64`: SSE-C key used for S3 PutObject in `standard`
  - `enc_wrapped_dek_customer`: customer-wrapped key metadata for `e2ee`
  - `outbound_dnssec_validate`: optional per-domain override for DNSSEC-validated TLSA lookup (`true`/`false`)
  - quota controls (optional): `quota_max_recipients_per_message`, `quota_hourly_send_limit`, `quota_daily_send_limit`, `quota_max_queued_jobs`
- Search indexing stays metadata-only in `e2ee` mode (no server-side parsed body blobs).
- Full TLS posture defaults:
  - `SMTP_OUTBOUND_TLS_MODE=required` enforces TLS delivery only (no plaintext fallback)
  - `SMTP_OUTBOUND_DANE_MODE=prefer` discovers TLSA records and prioritizes DANE-protected MX hosts (`require` enforces TLSA presence)
  - `SMTP_OUTBOUND_DNSSEC_VALIDATE=true` requires DNSSEC-validated TLSA lookup chain for DANE trust (can be overridden by `has_domain.outbound_dnssec_validate`)
  - DANE hosts are cryptographically verified against TLSA records (usage/selector/matching) before SMTP DATA
  - `SMTP_OUTBOUND_MTA_STS_ENFORCE=true` forces TLS when `_mta-sts.<domain>` TXT advertises `v=STSv1`
  - TLS failures are appended as JSONL reports in `SMTP_TLS_REPORT_DIR`
- OpenTelemetry tracing export can be enabled with `OTEL_ENABLED=true` and sent to `OTEL_EXPORTER_OTLP_ENDPOINT`.
- Delivery failures that expire or exceed attempts are marked `dead` in `outbound_queue`; DSN `.eml` artifacts are written under `data/bounces/`.
  - outbound delivery skips suppressed recipients via `suppression` table (`scope=address|domain`)
  - queue worker applies suppression upserts using deterministic bounce classification (address/domain policy)
  - queue worker emits structured tracing events for deliver/retry/dead-letter outcomes

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
    idempotencyKey: "send-2026-02-10-001"
  )
}
```
