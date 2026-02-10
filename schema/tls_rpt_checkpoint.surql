DEFINE TABLE OVERWRITE tls_rpt_checkpoint SCHEMAFULL;

DEFINE FIELD OVERWRITE domain ON tls_rpt_checkpoint
	TYPE string;

DEFINE FIELD OVERWRITE report_date ON tls_rpt_checkpoint
	TYPE string;

DEFINE FIELD OVERWRITE sent_at_epoch_secs ON tls_rpt_checkpoint
	TYPE int;

DEFINE FIELD OVERWRITE recipient_count ON tls_rpt_checkpoint
	TYPE int;

DEFINE INDEX OVERWRITE tls_rpt_checkpoint_domain_date_unique ON tls_rpt_checkpoint
	FIELDS domain, report_date
	UNIQUE;
