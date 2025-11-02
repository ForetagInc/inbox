DEFINE TABLE OVERWRITE email_attachment SCHEMAFULL;

DEFINE FIELD OVERWRITE email ON email_attachment
	TYPE record<email>;

DEFINE FIELD OVERWRITE part_id ON email_attachment
	TYPE string
	COMMENT 'MIME part path';

DEFINE FIELD OVERWRITE file_name ON email_attachment
	TYPE string;

DEFINE FIELD OVERWRITE content_type ON email_attachment
	TYPE string;

DEFINE FIELD OVERWRITE file_path ON email_attachment
	TYPE string
	COMMENT 'Object store or Bucket key / path';

DEFINE FIELD OVERWRITE size ON email_attachment
	TYPE int
	COMMENT 'Size in bytes';

DEFINE FIELD OVERWRITE hash ON email_attachment
	TYPE string
	COMMENT 'SHA256 of Attachment';

---
--- Indexes
---

DEFINE INDEX OVERWRITE attachment_by_message ON email_attachment
	FIELDS email;
