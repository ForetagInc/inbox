DEFINE TABLE OVERWRITE email_address SCHEMAFULL;

DEFINE FIELD OVERWRITE folders ON email_address
	COMPUTED <~mailbox_folder;

DEFINE FIELD OVERWRITE aliases ON email_address
	COMPUTED <~email_address;

DEFINE FIELD OVERWRITE full_address	ON email_address
	COMPUTED string::concat(username, '@', domain.domain)
	COMMENT 'Full address of the email address i.e. `user@example.com`';

DEFINE FIELD OVERWRITE username ON email_address
	TYPE string
	COMMENT 'Username of the email address i.e. `user` from `user@example.com`';

DEFINE FIELD OVERWRITE domain ON email_address
	TYPE record<domain_name>
	COMMENT 'Domain name of the email address i.e. `example.com` from `user@example.com`';

DEFINE FIELD OVERWRITE alias ON email_address
	TYPE option<record<email_address>>
	REFERENCE
	COMMENT 'The master alias for the current email address, if any';

DEFINE FIELD OVERWRITE last_reachable ON email_address
	TYPE option<datetime>
	COMMENT 'When this email was last reached out to successfully';

---
--- Indexes
---

DEFINE INDEX OVERWRITE unique_email ON email_address
	FIELDS username, domain
	UNIQUE;
