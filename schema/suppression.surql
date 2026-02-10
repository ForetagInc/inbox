DEFINE TABLE OVERWRITE suppression SCHEMAFULL;

DEFINE FIELD OVERWRITE scope ON suppression
	TYPE string
	ASSERT $value IN ["address", "domain"];

DEFINE FIELD OVERWRITE target ON suppression
	TYPE string;

DEFINE FIELD OVERWRITE reason ON suppression
	TYPE option<string>;

DEFINE FIELD OVERWRITE is_active ON suppression
	TYPE bool
	DEFAULT true;

DEFINE FIELD OVERWRITE expires_at_epoch_secs ON suppression
	TYPE option<int>;

DEFINE INDEX OVERWRITE suppression_scope_target_idx ON suppression
	FIELDS scope, target UNIQUE;
