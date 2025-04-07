from flask import Flask, request, render_template, send_file
import spacy
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from dotenv import load_dotenv
from api.virustotal import virustotal_bp, virustotal_lookup
from api.shodan import shodan_bp, shodan_lookup

load_dotenv()

nlp = spacy.load("cybersecurity_ner_model")
app = Flask(__name__)
app.register_blueprint(virustotal_bp)
app.register_blueprint(shodan_bp)

REPORT_FOLDER = "reports"
if not os.path.exists(REPORT_FOLDER):
    os.makedirs(REPORT_FOLDER)

@app.route('/', methods=['GET', 'POST'])
def index():
    entities = []
    chart_path = None
    text = ''
    report_name = ''
    vt_result = None
    shodan_result = None

    if request.method == 'POST':
        if 'vt_submit' in request.form:
            # ✅ VirusTotal lookup
            domain = request.form.get('domain')
            if domain:
                with app.test_request_context(json={'domain': domain}):
                    response = virustotal_lookup()
                    if response.status_code == 200:
                        vt_result = response.get_json()
                    else:
                        vt_result = {
                            "domain": domain,
                            "categories": "Unavailable",
                            "analysis": {}
                        }

        elif 'shodan_submit' in request.form:
            # ✅ Shodan lookup
            ip = request.form.get('ip')
            if ip:
                with app.test_request_context(json={'ip': ip}):
                    response = shodan_lookup()
                    if response.status_code == 200:
                        shodan_result = response.get_json()
                    else:
                        shodan_result = {
                            "ip": ip,
                            "organization": "Unavailable",
                            "os": "Unknown",
                            "ports": [],
                            "vulns": []
                        }

        else:
            # ✅ NLP Threat classification
            text = request.form['text']
            chart_type = request.form.get('chart_type', 'bar')

            doc = nlp(text)
            entities = [(ent.text, ent.label_) for ent in doc.ents]

            label_counts = {}
            for _, label in entities:
                label_counts[label] = label_counts.get(label, 0) + 1

            if label_counts:
                plt.figure(figsize=(6, 4))
                if chart_type == 'pie':
                    plt.pie(label_counts.values(), labels=label_counts.keys(), autopct='%1.1f%%', startangle=140)
                    plt.title("Entity Distribution (Pie Chart)")
                else:
                    plt.bar(label_counts.keys(), label_counts.values(), color="#1e90ff")
                    plt.xlabel("Entity Type")
                    plt.ylabel("Count")
                    plt.title("Entity Frequency (Bar Chart)")
                plt.tight_layout()
                chart_path = os.path.join("static", "chart.png")
                plt.savefig(chart_path)
                plt.close()

            timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')
            report_name = f"report_{timestamp}"
            txt_path = os.path.join(REPORT_FOLDER, f"{report_name}.txt")

            with open(txt_path, "w") as f:
                f.write("📝 Threat Analysis Report\n")
                f.write(f"📅 Timestamp: {timestamp}\n\n")
                f.write(f"Original Text:\n{text}\n\n")
                f.write("Detected Entities:\n")
                for ent, label in entities:
                    f.write(f" - {ent} ({label})\n")

            # PDF export
            pdf_path = os.path.join(REPORT_FOLDER, f"{report_name}.pdf")
            c = canvas.Canvas(pdf_path, pagesize=letter)
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, 750, "📝 Threat Analysis Report")
            c.setFont("Helvetica", 10)
            c.drawString(50, 735, f"Timestamp: {timestamp}")
            c.drawString(50, 715, "Original Input:")
            y = 700
            for line in text.split("\n"):
                c.drawString(60, y, line)
                y -= 15
            y -= 10
            c.drawString(50, y, "Detected Entities:")
            y -= 15
            for ent, label in entities:
                c.drawString(60, y, f"- {ent} ({label})")
                y -= 12
                if y < 80:
                    c.showPage()
                    y = 750
            if chart_path and os.path.exists(chart_path):
                c.showPage()
                c.drawImage(chart_path, 100, 300, width=400, preserveAspectRatio=True, mask='auto')
            c.save()

            with open("static/last_export.txt", "w") as f:
                f.write(report_name)

    return render_template(
        "index.html",
        entities=entities,
        chart=chart_path,
        vt_result=vt_result,
        shodan_result=shodan_result
    )

@app.route('/export')
def export_report():
    if os.path.exists("static/last_export.txt"):
        with open("static/last_export.txt", "r") as f:
            name = f.read().strip()
        txt_path = os.path.join(REPORT_FOLDER, f"{name}.txt")
        if os.path.exists(txt_path):
            return send_file(txt_path, as_attachment=True)
    return "⚠️ No report available to export."

@app.route('/export/pdf')
def export_pdf():
    if os.path.exists("static/last_export.txt"):
        with open("static/last_export.txt", "r") as f:
            name = f.read().strip()
        pdf_path = os.path.join(REPORT_FOLDER, f"{name}.pdf")
        if os.path.exists(pdf_path):
            return send_file(pdf_path, as_attachment=True)
    return "⚠️ No PDF report available yet."

if __name__ == '__main__':
    app.run(debug=True)



