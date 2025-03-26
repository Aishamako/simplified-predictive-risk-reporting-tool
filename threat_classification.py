import spacy

# ✅ Load trained model
nlp = spacy.load("cybersecurity_ner_model")

# ✅ Example threat descriptions (can be changed to real inputs)
examples = [
    "A zero-day SQL Injection attack was launched against Apache servers.",
    "DDoS attacks continue to be a major concern for government infrastructure.",
    "Phishing emails targeting employees were sent by hackers.",
    "The Windows kernel is vulnerable to buffer overflow exploits.",
]

# ✅ Display predictions
for sentence in examples:
    doc = nlp(sentence)
    print(f"\n🔍 Input: {sentence}")
    print("Detected Entities:")
    for ent in doc.ents:
        print(f"  • {ent.text} → {ent.label_}")
