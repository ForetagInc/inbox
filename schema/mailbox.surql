DEFINE TABLE OVERWRITE mailbox SCHEMAFULL;

DEFINE FIELD OVERWRITE email_address ON mailbox
	TYPE record<email_address>;

DEFINE FIELD OVERWRITE name ON mailbox
	TYPE string;

DEFINE FIELD OVERWRITE parent ON mailbox
	TYPE option<record<mailbox>>;

DEFINE FIELD OVERWRITE special_use ON mailbox
	TYPE option<string>;

DEFINE FIELD OVERWRITE uid_validity ON mailbox
	TYPE int
	COMMENT 'RFC 3501';

DEFINE FIELD OVERWRITE next_uid ON mailbox
	TYPE int;

DEFINE FIELD OVERWRITE modseq ON mailbox
	TYPE int
	COMMENT 'RFC 7162 (CONDSTORE/QRESYNC)';

---
--- Indexes
---

DEFINE INDEX OVERWRITE mailbox_email_address ON mailbox
	FIELDS email_address, name
	UNIQUE;
