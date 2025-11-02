DEFINE TABLE OVERWRITE email SCHEMAFULL;

DEFINE FIELD OVERWRITE subject ON email
	TYPE string;

DEFINE FIELD OVERWRITE from ON email
	TYPE array<record<email_address>>;

DEFINE FIELD OVERWRITE to ON email
	TYPE array<record<email_address>>;

DEFINE FIELD OVERWRITE cc ON email
	TYPE array<record<email_address>>;

DEFINE FIELD OVERWRITE bcc ON email
	TYPE array<record<email_address>>
	DEFAULT [];
