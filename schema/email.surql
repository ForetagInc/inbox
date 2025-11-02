DEFINE TABLE OVERWRITE email SCHEMAFULL;

-- Identity
DEFINE FIELD OVERWRITE message_id ON email
	TYPE string;

DEFINE FIELD OVERWRITE content_hash ON email
	TYPE string
	COMMENT 'SHA256 hash of the email content';

-- Headers (RFC 5322)
DEFINE FIELD OVERWRITE date ON email
	TYPE option<datetime>;

DEFINE FIELD OVERWRITE subject ON email
	TYPE string;

DEFINE FIELD OVERWRITE subject_normalized ON email
	TYPE string;

-- Addresses (RFC 5322) - Store rendered Mailboxes
DEFINE FIELD OVERWRITE references ON email
	TYPE array<string>
	DEFAULT [];

DEFINE FIELD OVERWRITE from ON email
	TYPE array<record<email_address>>;

DEFINE FIELD OVERWRITE sender_address ON email
	TYPE option<string>
	COMMENT 'RFC 6854 Sender:';

DEFINE FIELD OVERWRITE reply_to ON email
	TYPE array<string>;

DEFINE FIELD OVERWRITE to ON email
	TYPE array<record<email_address>>;

DEFINE FIELD OVERWRITE cc ON email
	TYPE array<record<email_address>>;

DEFINE FIELD OVERWRITE bcc ON email
	TYPE array<record<email_address>>
	DEFAULT [];

-- Threading
DEFINE FIELD OVERWRITE depth ON email
	TYPE int;

-- MIME
DEFINE FIELD OVERWRITE mime_root_ct ON email
	TYPE string
	COMMENT 'e.g. multipart/alternative';

DEFINE FIELD OVERWRITE size ON email
	TYPE int
	COMMENT 'Size in bytes';

DEFINE FIELD OVERWRITE snippet ON email
	TYPE string
	COMMENT 'Short preview of the email content';

DEFINE FIELD OVERWRITE tags ON email
	TYPE array<string>
	DEFAULT [];

-- Auth
DEFINE FIELD OVERWRITE spf ON email
	TYPE option<object>;

DEFINE FIELD OVERWRITE dkim ON email
	TYPE option<object>;

DEFINE FIELD OVERWRITE dmarc ON email
	TYPE option<object>;

-- Storage
DEFINE FIELD OVERWRITE blob_path ON email
	TYPE string;

DEFINE FIELD OVERWRITE blob_sha ON email
	TYPE string;

DEFINE FIELD OVERWRITE envelope_enc ON email
	TYPE option<bytes>;

-- Lifecycle
DEFINE FIELD OVERWRITE kind ON email
		TYPE string
		ASSERT $value IN ['inbound', 'outbound', 'draft', 'scheduled'];

DEFINE FIELD OVERWRITE recurrence ON email
	TYPE option<string>;

DEFINE FIELD OVERWRITE internal_date ON email
		TYPE datetime;

DEFINE FIELD OVERWRITE send_at ON email
		TYPE option<datetime>;

DEFINE FIELD OVERWRITE created_at ON email
		TYPE datetime;

---
--- Indexes
---

DEFINE INDEX OVERWRITE unique_message_id ON email
	FIELDS message_id
	UNIQUE;

DEFINE INDEX OVERWRITE search_subject ON email
	FIELDS subject
	FULLTEXT ANALYZER english_email BM25;
