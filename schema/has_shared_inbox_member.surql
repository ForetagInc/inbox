DEFINE TABLE OVERWRITE has_shared_inbox_member SCHEMAFULL
	TYPE RELATION
	IN shared_inbox
	OUT account
	ENFORCED;

DEFINE FIELD OVERWRITE role ON has_shared_inbox_member
	TYPE string
	ASSERT $value IN ["owner", "member"];

DEFINE FIELD OVERWRITE can_send_as ON has_shared_inbox_member
	TYPE bool
	DEFAULT false;

DEFINE FIELD OVERWRITE can_assign ON has_shared_inbox_member
	TYPE bool
	DEFAULT false;

DEFINE FIELD OVERWRITE is_active ON has_shared_inbox_member
	TYPE bool
	DEFAULT true;

DEFINE INDEX OVERWRITE shared_member_unique ON has_shared_inbox_member
	FIELDS in, out
	UNIQUE;
