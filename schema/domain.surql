DEFINE TABLE OVERWRITE domain SCHEMAFULL;

DEFINE FIELD OVERWRITE fqdn ON domain
	TYPE string
	ASSERT string::len($value) > 0;

DEFINE INDEX OVERWRITE unique_domain_fqdn ON domain
	FIELDS fqdn
	UNIQUE;
