DEFINE TABLE OVERWRITE outbound_delivery SCHEMAFULL;

DEFINE FIELD OVERWRITE job_id ON outbound_delivery
	TYPE string;

DEFINE FIELD OVERWRITE delivered_at_epoch_secs ON outbound_delivery
	TYPE int;

DEFINE FIELD OVERWRITE org_id ON outbound_delivery
	TYPE option<string>;

DEFINE FIELD OVERWRITE actor_account ON outbound_delivery
	TYPE option<string>;

DEFINE FIELD OVERWRITE shared_inbox ON outbound_delivery
	TYPE option<string>;

DEFINE INDEX OVERWRITE outbound_delivery_job_id_unique ON outbound_delivery
	FIELDS job_id
	UNIQUE;

DEFINE INDEX OVERWRITE outbound_delivery_org_time_idx ON outbound_delivery
	FIELDS org_id, delivered_at_epoch_secs;
