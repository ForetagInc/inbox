DEFINE TABLE OVERWRITE smtp_rate_limit SCHEMAFULL;

DEFINE FIELD OVERWRITE counter_key ON smtp_rate_limit
	TYPE string;

DEFINE FIELD OVERWRITE count ON smtp_rate_limit
	TYPE int;

DEFINE FIELD OVERWRITE expires_at_epoch_secs ON smtp_rate_limit
	TYPE int;

DEFINE INDEX OVERWRITE smtp_rate_limit_counter_key_unique ON smtp_rate_limit
	FIELDS counter_key UNIQUE;
