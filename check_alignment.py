import spacy
from spacy.training import offsets_to_biluo_tags

# ✅ Load the trained model for consistent tokenizer rules
nlp = spacy.load("cybersecurity_ner_model")

# ✅ Sample sentence for alignment checking
text = "A new SQL Injection vulnerability has been found in Apache servers."
entities = [(8, 21, "VULNERABILITY"), (49, 55, "PRODUCT")]

# ✅ Tokenize and verify alignment
doc = nlp(text)
print("Tokens:", [token.text for token in doc])
tags = offsets_to_biluo_tags(doc, [(start, end, label) for start, end, label in entities])
print("BILUO Tags:", tags)
