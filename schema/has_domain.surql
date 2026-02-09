DEFINE TABLE OVERWRITE has_domain SCHEMAFULL
	TYPE RELATION
	IN organization
	OUT domain;

DEFINE FIELD OVERWRITE dkim_selector ON has_domain
	TYPE option<string>;

DEFINE FIELD OVERWRITE dkim_private_key_b64_pkcs8 ON has_domain
	TYPE option<string>;

DEFINE FIELD OVERWRITE dkim_headers ON has_domain
	TYPE option<array<string>>;

DEFINE FIELD OVERWRITE require_spf_pass ON has_domain
	TYPE option<bool>;

DEFINE FIELD OVERWRITE require_dkim_pass ON has_domain
	TYPE option<bool>;

DEFINE FIELD OVERWRITE require_dmarc_pass ON has_domain
	TYPE option<bool>;

DEFINE FIELD OVERWRITE is_active ON has_domain
	TYPE bool
	DEFAULT true;

DEFINE INDEX OVERWRITE has_domain_unique_pair ON has_domain
	FIELDS in, out
	UNIQUE;
