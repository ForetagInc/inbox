DEFINE TABLE OVERWRITE has_email_state SCHEMAFULL
	TYPE RELATION
	IN account
	OUT has_email_delivery
	ENFORCED;

DEFINE FIELD OVERWRITE seen ON has_email_state
	TYPE bool
	DEFAULT false;

DEFINE FIELD OVERWRITE pinned ON has_email_state
	TYPE bool
	DEFAULT false;

DEFINE FIELD OVERWRITE labels ON has_email_state
	TYPE set<string>;

DEFINE FIELD OVERWRITE snooze_until ON has_email_state
	TYPE option<datetime>;

DEFINE FIELD OVERWRITE last_viewed ON has_email_state
	TYPE option<datetime>;

---
--- Indexes
---

DEFINE INDEX OVERWRITE unique_state ON has_email_state
	FIELDS in, out
	UNIQUE;
