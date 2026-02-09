DEFINE TABLE OVERWRITE outbound_delivery SCHEMAFULL;

DEFINE FIELD OVERWRITE job_id ON outbound_delivery
	TYPE string;

DEFINE FIELD OVERWRITE delivered_at_epoch_secs ON outbound_delivery
	TYPE int;

DEFINE INDEX OVERWRITE outbound_delivery_job_id_unique ON outbound_delivery
	FIELDS job_id
	UNIQUE;
