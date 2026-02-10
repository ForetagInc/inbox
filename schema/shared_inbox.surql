DEFINE TABLE OVERWRITE shared_inbox SCHEMAFULL;

DEFINE FIELD OVERWRITE address ON shared_inbox
	TYPE string;

DEFINE FIELD OVERWRITE domain ON shared_inbox
	TYPE string;

DEFINE FIELD OVERWRITE display_name ON shared_inbox
	TYPE string;

DEFINE FIELD OVERWRITE is_active ON shared_inbox
	TYPE bool
	DEFAULT true;

DEFINE FIELD OVERWRITE mailbox ON shared_inbox
	TYPE record<mailbox>;

DEFINE INDEX OVERWRITE shared_inbox_address_unique ON shared_inbox
	FIELDS address
	UNIQUE;
