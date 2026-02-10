DEFINE ANALYZER OVERWRITE english_email
	TOKENIZERS blank, class
	FILTERS lowercase, edgengram(1,16);
