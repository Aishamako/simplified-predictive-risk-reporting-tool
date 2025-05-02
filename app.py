from flask import Flask, request, render_template, send_file, session, redirect, url_for
import spacy
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from api.virustotal import virustotal_bp, virustotal_lookup
from api.shodan import shodan_bp, shodan_lookup
import smtplib
from email.message import EmailMessage
import random
import json

# Load environment variables
load_dotenv()

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = 587  # common port, you can adjust if needed

def send_2fa_email(to_email, code):
    msg = EmailMessage()
    msg['Subject'] = '🔐 Your 2FA Code for Risk Reporting Tool'
    msg['From'] = EMAIL_USER
    msg['To'] = to_email
    msg.set_content(f""" 
Hello,

Your 2FA verification code is: {code}

Please enter this code on the website to complete login.

Regards,
Cybersecurity Risk Tool
""")
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
            print("✅ 2FA code sent via Mailtrap.")
    except Exception as e:
        print("❌ Error sending 2FA email:", e)

nlp = spacy.load("cybersecurity_ner_model")
app = Flask(__name__)
app.secret_key = 'your_super_secret_key'
app.register_blueprint(virustotal_bp)
app.register_blueprint(shodan_bp)

REPORT_FOLDER = "reports"
if not os.path.exists(REPORT_FOLDER):
    os.makedirs(REPORT_FOLDER)

RECOMMENDATIONS = {
    "VULNERABILITY": "Apply vendor patches promptly and scan for known vulnerabilities regularly.",
    "EXPLOIT": "Implement intrusion detection systems and monitor unusual behavior.",
    "ACTOR": "Educate staff on social engineering and enforce strong access controls.",
    "ATTACK_TYPE": "Use firewall rules and rate limiting to protect against attack vectors.",
    "PRODUCT": "Ensure software is up-to-date and configured securely."
}

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    entities = []
    chart_path = None
    text = ''
    report_name = ''
    vt_result = None
    shodan_result = None
    recommendations = []

    if request.method == 'POST':
        if 'vt_submit' in request.form:
            domain = request.form.get('domain')
            if domain:
                with app.test_request_context(json={'domain': domain}):
                    response = virustotal_lookup()
                    vt_result = response.get_json() if response.status_code == 200 else {
                        "domain": domain, "categories": "Unavailable", "analysis": {}
                    }

        elif 'shodan_submit' in request.form:
            ip = request.form.get('ip')
            if ip:
                with app.test_request_context(json={'ip': ip}):
                    response = shodan_lookup()
                    shodan_result = response.get_json() if response.status_code == 200 else {
                        "ip": ip, "organization": "Unavailable", "os": "Unknown", "ports": [], "vulns": []
                    }

        else:
            text = request.form['text']
            chart_type = request.form.get('chart_type', 'bar')
            doc = nlp(text)
            entities = [(ent.text, ent.label_) for ent in doc.ents]

            seen_labels = set()
            for _, label in entities:
                if label in RECOMMENDATIONS and label not in seen_labels:
                    recommendations.append(RECOMMENDATIONS[label])
                    seen_labels.add(label)

            label_counts = {}
            for _, label in entities:
                label_counts[label] = label_counts.get(label, 0) + 1

            if label_counts:
                plt.figure(figsize=(6, 4))
                if chart_type == 'pie':
                    plt.pie(label_counts.values(), labels=label_counts.keys(), autopct='%1.1f%%', startangle=140)
                else:
                    plt.bar(label_counts.keys(), label_counts.values(), color="#1e90ff")
                    plt.xlabel("Entity Type")
                    plt.ylabel("Count")
                plt.title("Entity Summary")
                plt.tight_layout()
                chart_path = os.path.join("static", "chart.png")
                plt.savefig(chart_path)
                plt.close()

            timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')
            report_name = f"report_{timestamp}"
            txt_path = os.path.join(REPORT_FOLDER, f"{report_name}.txt")
            pdf_path = os.path.join(REPORT_FOLDER, f"{report_name}.pdf")

            with open(txt_path, "w") as f:
                f.write("📝 Threat Analysis Report\n")
                f.write(f"📅 Timestamp: {timestamp}\n\n")
                f.write(f"Original Text:\n{text}\n\n")
                f.write("Detected Entities:\n")
                for ent, label in entities:
                    f.write(f" - {ent} ({label})\n")
                f.write("\nRecommendations:\n")
                for rec in recommendations:
                    f.write(f" - {rec}\n")

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
            y -= 10
            c.drawString(50, y, "Recommendations:")
            y -= 15
            for rec in recommendations:
                c.drawString(60, y, f"- {rec}")
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

    return render_template("index.html", entities=entities, chart=chart_path, vt_result=vt_result, shodan_result=shodan_result)

@app.route('/export')
def export_report():
    if os.path.exists("static/last_export.txt"):
        with open("static/last_export.txt", "r") as f:
            name = f.read().strip()
        path = os.path.join(REPORT_FOLDER, f"{name}.txt")
        if os.path.exists(path):
            return send_file(path, as_attachment=True)
    return "⚠️ No report available."

@app.route('/export/pdf')
def export_pdf():
    if os.path.exists("static/last_export.txt"):
        with open("static/last_export.txt", "r") as f:
            name = f.read().strip()
        path = os.path.join(REPORT_FOLDER, f"{name}.pdf")
        if os.path.exists(path):
            return send_file(path, as_attachment=True)
    return "⚠️ No PDF report available."

@app.route('/', endpoint='home')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = request.form['username']
        pw = request.form['password']
        hashed_pw = generate_password_hash(pw)

        if not os.path.exists("users.json"):
            with open("users.json", "w") as f:
                json.dump({}, f)

        with open("users.json", "r") as f:
            users = json.load(f)

        if user in users:
            return "⚠️ User already exists."
        users[user] = hashed_pw
        with open("users.json", "w") as f:
            json.dump(users, f)
        return redirect(url_for('login'))
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        pw = request.form['password']
        with open("users.json", "r") as f:
            users = json.load(f)
        if user in users and check_password_hash(users[user], pw):
            # ✅ Handle marker demo bypass
            print("Trying to login:", user, pw)
            print("Available users:", users.keys())
            print("Stored hash:", users.get(user))
 
            if user == "marker@demo.com":
                session['user'] = user
                session['2fa_verified'] = True
                return redirect(("/dashboard"))

            # ✅ Step 3: Generate and store 2FA code
            code = str(random.randint(100000, 999999))
            session['user'] = user
            session['2fa_code'] = code
            session['2fa_verified'] = False
            send_2fa_email(user, code)
            return redirect(url_for('verify_2fa'))
    
        else:
            return "⚠️ Invalid login."
    return render_template("login.html")

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'user' not in session or '2fa_code' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if request.form['code'] == session['2fa_code']:
            session['2fa_verified'] = True
            return redirect(url_for('dashboard'))
        return "⚠️ Invalid 2FA code."
    return render_template("verify_2fa.html", user=session['user'], code=session['2fa_code'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.before_request
def restrict_access():
    # Routes that don’t need authentication
    public_routes = ['login', 'register', 'verify_2fa', 'static', 'home', None]

    # If accessing a public route, let it pass
    if request.endpoint in public_routes:
        return

    # If user is not logged in
    if 'user' not in session:
        return redirect(url_for('login'))

    # If user is logged in but not verified
    if not session.get('2fa_verified'):
        return redirect(url_for('verify_2fa'))

@app.route('/history')
def history():
    report_files = sorted(os.listdir(REPORT_FOLDER), reverse=True)
    return render_template("history.html", reports=report_files)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)





