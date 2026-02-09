DEFINE TABLE OVERWRITE shared_inbox_event SCHEMAFULL;

DEFINE FIELD OVERWRITE shared_inbox ON shared_inbox_event
	TYPE record<shared_inbox>;

DEFINE FIELD OVERWRITE actor ON shared_inbox_event
	TYPE record<account>;

DEFINE FIELD OVERWRITE event_type ON shared_inbox_event
	TYPE string
	ASSERT $value IN ["send_as", "read", "state_change", "assignment_change"];

DEFINE FIELD OVERWRITE email_delivery ON shared_inbox_event
	TYPE option<record<has_email_delivery>>;

DEFINE FIELD OVERWRITE created_at ON shared_inbox_event
	TYPE datetime;

DEFINE INDEX OVERWRITE shared_inbox_event_by_box_time ON shared_inbox_event
	FIELDS shared_inbox, created_at DESC;
