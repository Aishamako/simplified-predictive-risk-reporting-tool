import spacy

# ✅ Load your trained model
nlp = spacy.load("cybersecurity_ner_model")

# ✅ Sample test inputs
test_texts = [
    "A new SQL Injection vulnerability has been found in Apache servers.",
    "DDoS attacks are increasing due to botnets.",
    "Hackers use phishing attacks to steal login credentials.",
    "A buffer overflow in Windows kernel can allow remote code execution.",
    "The system is vulnerable to SQL Injection.",
    "SQL Injection is a major security risk.",
    "Hackers used SQL Injection to steal data.",
    "SQL Injection attacks are dangerous.",
    "Users reported a SQL Injection vulnerability yesterday.",
    "A vulnerability known as SQL Injection has been exploited.",
    "Apache servers are affected by SQL Injection.",
    "Security teams found a new SQL Injection in Apache systems.",
    "He used a SQL Injection.",
    "He was attacked using SQL Injection."
]

# ✅ Run model and print outputs
for text in test_texts:
    doc = nlp(text)
    print(f"🔍 Debugging: '{text}'")
    print("Tokens:", [token.text for token in doc])
    print("Entities Found:", [(ent.text, ent.label_) for ent in doc.ents])
    print("-" * 60)


