DEFINE TABLE OVERWRITE email SCHEMAFULL;

-- Headers
DEFINE FIELD OVERWRITE message_id ON email
	TYPE string;

DEFINE FIELD OVERWRITE date ON email
	TYPE option<datetime>;

DEFINE FIELD OVERWRITE internal_date ON email
	TYPE datetime;

DEFINE FIELD OVERWRITE subject ON email
	TYPE string;

DEFINE FIELD OVERWRITE subject_normalized ON email
	TYPE string;

-- Addresses (RFC 5322) - Store rendered Mailboxes

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

---
--- Indexes
---

DEFINE INDEX OVERWRITE unique_message_id ON email
	FIELDS message_id
	UNIQUE;

DEFINE INDEX OVERWRITE search_subject ON email
	FIELDS subject
	FULLTEXT ANALYZER english_email BM25;
