DEFINE TABLE OVERWRITE has_email_delivery SCHEMAFULL
	TYPE RELATION
	IN email
	OUT mailbox
	ENFORCED;

DEFINE FIELD OVERWRITE uid ON has_email_delivery
	TYPE int;

DEFINE FIELD OVERWRITE modseq ON has_email_delivery
	TYPE int;

DEFINE FIELD OVERWRITE flags ON has_email_delivery
	TYPE set<string>;

DEFINE FIELD OVERWRITE keywords ON has_email_delivery
	TYPE set<string>;

DEFINE FIELD OVERWRITE status ON has_email_delivery
	TYPE string
	ASSERT $value IN ['open', 'pending', 'closed', 'spam', 'archived']
	DEFAULT 'open';

DEFINE FIELD OVERWRITE assignee ON has_email_delivery
	TYPE option<record<account>>;

DEFINE FIELD OVERWRITE tags ON has_email_delivery
	TYPE set<string>;

DEFINE FIELD OVERWRITE priority ON has_email_delivery
	TYPE int
	DEFAULT 0;

DEFINE FIELD OVERWRITE due_at ON has_email_delivery
	TYPE option<datetime>;

DEFINE FIELD OVERWRITE received_at ON has_email_delivery
	TYPE datetime;

---
--- Indexes
---

DEFINE INDEX OVERWRITE by_uid
	FIELDS out, uid
	UNIQUE;

DEFINE INDEX OVERWRITE by_ts
	FIELDS out, received_at
	DESC;

DEFINE INDEX OVERWRITE by_flags
	FIELDS out, flags;
