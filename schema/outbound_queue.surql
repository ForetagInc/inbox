DEFINE TABLE OVERWRITE outbound_queue SCHEMAFULL;

DEFINE FIELD OVERWRITE job_id ON outbound_queue
	TYPE string;

DEFINE FIELD OVERWRITE created_at_epoch_secs ON outbound_queue
	TYPE int;

DEFINE FIELD OVERWRITE expires_at_epoch_secs ON outbound_queue
	TYPE int;

DEFINE FIELD OVERWRITE next_attempt_at_epoch_secs ON outbound_queue
	TYPE int;

DEFINE FIELD OVERWRITE attempts ON outbound_queue
	TYPE int;

DEFINE FIELD OVERWRITE status ON outbound_queue
	TYPE string
	ASSERT $value IN ["queued", "processing", "dead"];

DEFINE FIELD OVERWRITE lease_owner ON outbound_queue
	TYPE option<string>;

DEFINE FIELD OVERWRITE lease_until_epoch_secs ON outbound_queue
	TYPE option<int>;

DEFINE FIELD OVERWRITE last_error ON outbound_queue
	TYPE option<string>;

DEFINE FIELD OVERWRITE payload_kind ON outbound_queue
	TYPE string;

DEFINE FIELD OVERWRITE payload_json ON outbound_queue
	TYPE string;

DEFINE INDEX OVERWRITE outbound_queue_job_id_unique ON outbound_queue
	FIELDS job_id
	UNIQUE;

DEFINE INDEX OVERWRITE outbound_queue_due_idx ON outbound_queue
	FIELDS status, next_attempt_at_epoch_secs, lease_until_epoch_secs;
