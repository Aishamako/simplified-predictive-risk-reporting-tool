import spacy
import random
from spacy.training import Example
from spacy.tokenizer import Tokenizer

# ✅ Load blank English model
nlp = spacy.blank("en")

# ✅ Only add valid special case (no period)
special_cases = {
    "SQL Injection": [{"ORTH": "SQL Injection"}],
}
nlp.tokenizer = Tokenizer(nlp.vocab, rules=special_cases)

# ✅ Add NER pipe
if "ner" not in nlp.pipe_names:
    ner = nlp.add_pipe("ner", last=True)
else:
    ner = nlp.get_pipe("ner")

# ✅ Entity labels
LABELS = ["VULNERABILITY", "EXPLOIT", "ACTOR", "ATTACK_TYPE", "PRODUCT"]
for label in LABELS:
    ner.add_label(label)

# ✅ Finalized training data (no punctuation inside entity spans)
TRAIN_DATA = [
    (
        "A new SQL Injection vulnerability has been found in Apache servers.",
        {"entities": [(6, 21, "VULNERABILITY"), (49, 55, "PRODUCT")]}
    ),
    (
        "DDoS attacks are increasing due to botnets.",
        {"entities": [(0, 4, "ATTACK_TYPE")]}
    ),
    (
        "Hackers use phishing attacks to steal login credentials.",
        {"entities": [(0, 7, "ACTOR")]}
    ),
    (
        "A buffer overflow in Windows kernel can allow remote code execution.",
        {"entities": [(2, 17, "EXPLOIT"), (21, 28, "PRODUCT")]}
    ),
    (
        "The system is vulnerable to SQL Injection.",
        {"entities": [(28, 40, "VULNERABILITY")]}  # Without period
    ),
    (
        "SQL Injection is a major security risk.",
        {"entities": [(0, 13, "VULNERABILITY")]}
    ),
    (
        "Hackers used SQL Injection to steal data.",
        {"entities": [(0, 7, "ACTOR"), (13, 26, "VULNERABILITY")]}
    ),
    (
        "SQL Injection attacks are dangerous.",
        {"entities": [(0, 13, "VULNERABILITY")]}
    ),
    (
        "Users reported a SQL Injection vulnerability yesterday.",
        {"entities": [(17, 30, "VULNERABILITY")]}
    ),
    (
        "SQL Injection can be used to access unauthorized data.",
        {"entities": [(0, 13, "VULNERABILITY")]}
    ),
    (
        "A vulnerability known as SQL Injection has been exploited.",
        {"entities": [(25, 38, "VULNERABILITY")]}
    ),
    (
        "He was attacked using SQL Injection.",
        {"entities": [(24, 36, "VULNERABILITY")]}  # Adjusted for no period
    ),
    (
        "Apache servers are affected by SQL Injection.",
        {"entities": [(0, 6, "PRODUCT"), (32, 44, "VULNERABILITY")]}
    ),
    (
        "Security teams found a new SQL Injection in Apache systems.",
        {"entities": [(28, 40, "VULNERABILITY"), (44, 50, "PRODUCT")]}
    ),
    (
        "He used a SQL Injection.",
        {"entities": [(10, 23, "VULNERABILITY")]}  # No period included
    )
]

# ✅ Convert training data to spaCy format with alignment check
examples = []
for text, annotations in TRAIN_DATA:
    doc = nlp.make_doc(text)
    ents = []

    print(f"\n🔍 Text: '{text}'")
    print("🔹 Tokens:", [token.text for token in doc])

    for start, end, label in annotations["entities"]:
        print(f"🔹 Checking span: text[{start}:{end}] = '{text[start:end]}' → Label: {label}")
        span = doc.char_span(start, end, label=label, alignment_mode="contract")
        if span is None:
            print(f"⚠️ Skipping misaligned entity: '{text[start:end]}'")
        else:
            ents.append(span)

    doc.ents = ents
    examples.append(Example.from_dict(doc, {"entities": [(ent.start_char, ent.end_char, ent.label_) for ent in ents]}))

# ✅ Train the model
optimizer = nlp.begin_training()
for i in range(100):
    random.shuffle(examples)
    losses = {}
    for example in examples:
        nlp.update([example], losses=losses)
    print(f"✅ Iteration {i + 1}, Losses: {losses}")

# ✅ Save the trained model
nlp.to_disk("cybersecurity_ner_model")
print("\n🎉 Training complete and model saved to 'cybersecurity_ner_model'!")
