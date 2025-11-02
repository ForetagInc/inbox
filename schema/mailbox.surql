DEFINE TABLE OVERWRITE mailbox SCHEMAFULL;

DEFINE FIELD OVERWRITE account ON mailbox
	TYPE record<account>;

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

DEFINE INDEX OVERWRITE mailbox_for_account ON mailbox
	FIELDS account, name
	UNIQUE;
