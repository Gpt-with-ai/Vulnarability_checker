from flask import Flask, render_template, request ,send_from_directory,session,send_file
from flask_session import Session
from googlesearch import search
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import quote
import time, os, socket, ssl, json
from datetime import datetime
from groq import Groq
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import make_response
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from io import BytesIO
from fpdf import FPDF
from docx import Document
import textwrap

import uuid

report_cache = {}  # temporary in-memory store

# ======= CONFIG =======

NVD_API_KEY = os.getenv("NVD_API_KEY")
if not NVD_API_KEY:
    raise ValueError("NVD_API_KEY environment variable is required")

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_API_KEY:
    raise ValueError("GROQ_API_KEY environment variable is required")
client = Groq(api_key=GROQ_API_KEY)

MODEL = "moonshotai/kimi-k2-instruct"
DEFAULT_LOOKBACK_DAYS = int(os.getenv("DEFAULT_LOOKBACK_DAYS", 180))
# ======================

app = Flask(__name__)
client = Groq(api_key=GROQ_API_KEY)
COMMON_TLDS = [".com", ".org", ".net", ".ai", ".dev", ".io"]
RISKY_PORTS = [21, 23, 25, 110, 143, 3389]
app.secret_key = 'kejbsughuw'


app.config['SESSION_TYPE'] = 'filesystem'
# app.config['SESSION_FILE_DIR'] = os.path.join(app.root_path, 'flask_sessions')    # or any safe writable directory
app.config['SESSION_PERMANENT'] = False

Session(app)
# ================== NVD Vulnerability Search ==================
def search_vulnerabilities_nvd(app_name):
    try:
        q = app_name.strip()
        if q.lower() in {"vs code", "vscode"}:
            q = "Visual Studio Code"
        elif q.lower() in {"chrome", "google chrome"}:
            q = "Google Chrome"
        elif q.lower() in {"firefox", "mozilla firefox"}:
            q = "Mozilla Firefox"

        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote(q)}&resultsPerPage=200"
        headers = {"User-Agent": "Mozilla/5.0"}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        time.sleep(0.6)

        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code != 200:
            return []

        data = response.json()
        cves = data.get("vulnerabilities", [])
        parsed = []

        for cve_item in cves:
            try:
                cve_data = cve_item.get("cve", {})
                cve_id = cve_data.get("id", "Unknown")
                descriptions = cve_data.get("descriptions", [])
                description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description")

                metrics = cve_data.get("metrics", {})
                cvss_score = "N/A"
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and len(metrics[key]) > 0:
                        cvss_score = metrics[key][0].get("cvssData", {}).get("baseScore", "N/A")
                        break

                if isinstance(cvss_score, (int, float)):
                    cvss_score = float(cvss_score)
                elif isinstance(cvss_score, str) and cvss_score.replace('.', '', 1).isdigit():
                    cvss_score = float(cvss_score)

                parsed.append({
                    "id": cve_id,
                    "summary": description[:200] + "..." if len(description) > 200 else description,
                    "cvss": cvss_score
                })
            except:
                continue

        return parsed
    except:
        return []

def analyze_risk(cve_list):
    if not cve_list:
        return "None", True, {}

    critical = sum(1 for cve in cve_list if isinstance(cve['cvss'], (int, float)) and 9.0 <= cve['cvss'] <= 10.0)
    high     = sum(1 for cve in cve_list if isinstance(cve['cvss'], (int, float)) and 7.0 <= cve['cvss'] < 9.0)
    medium   = sum(1 for cve in cve_list if isinstance(cve['cvss'], (int, float)) and 4.0 <= cve['cvss'] < 7.0)
    low      = sum(1 for cve in cve_list if isinstance(cve['cvss'], (int, float)) and 0.1 <= cve['cvss'] < 4.0)
    none_score = sum(1 for cve in cve_list if cve['cvss'] == 0.0)

    scores = [cve['cvss'] for cve in cve_list if isinstance(cve['cvss'], (int, float))]
    if not scores:
        return "None", True, {}

    avg_score = round(sum(scores) / len(scores), 2)
    severity, safe_to_install = "Unknown", False
    if avg_score >= 9.0: severity = "Critical"
    elif avg_score >= 8.5: severity = "High"
    elif avg_score >= 4.0: severity, safe_to_install = "Medium", True
    elif avg_score >= 0.1: severity, safe_to_install = "Low", True
    elif avg_score == 0.0: severity, safe_to_install = "None", True

    breakdown = {
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "none": none_score,
        "total": len(cve_list)
    }
    return severity, safe_to_install, breakdown

# ================== Version & Release Date ==================
def extract_version_and_date(url):
    try:
        response = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(response.text, "html.parser")
        version, date = None, None

        if "github.com" in url and "/releases" in url:
            version_tag = soup.select_one("a[href*='/tag/'] .css-truncate-target, h1.d-inline.mr-3, span.css-truncate-target, a.Link--primary[href*='/tag/']")
            if version_tag:
                version = version_tag.get_text(strip=True)
            date_tag = soup.select_one("relative-time, time-ago")
            if date_tag:
                date = date_tag.get("datetime") or date_tag.get("title") or date_tag.get_text(strip=True)
        else:
            text = soup.get_text(" ", strip=True)
            version_match = re.search(r"\bv?(\d+\.\d+\.\d+(?:\.\d+)?)\b", text)
            if version_match:
                version = version_match.group(1)

        return version, date
    except:
        return None, None

# ================== App Description ==================
def fetch_app_description(app_name, search_results):
    # Try Wikipedia with multiple candidates
    try:
        title = app_name.strip()
        candidates = [
            title,
            title.title(),
            title.replace(' ', '_'),
            title.replace(' ', '_').title(),
            f"{title} (software)",
        ]
       
        # Add specific aliases
        if title.lower() in {"vs code", "vscode"}:
            candidates.insert(0, "Visual Studio Code")
        elif title.lower() in {"chrome", "google chrome"}:
            candidates.insert(0, "Google Chrome")
 
        for cand in candidates:
            try:
                url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{quote(cand)}"
                response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                if response.status_code == 200:
                    data = response.json()
                    extract = data.get("extract")
                    page = (data.get("content_urls", {})
                               .get("desktop", {})
                               .get("page"))
                    if extract and len(extract.strip()) > 10:
                        app.logger.info(f"Found Wikipedia description for: {cand}")
                        return extract, page
            except Exception:
                continue
               
    except Exception:
        app.logger.exception("Wikipedia lookup failed")
 
    # Fallback: GitHub repo description
    try:
        for url in search_results:
            if "github.com" in url and "/releases" not in url:
                r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                soup = BeautifulSoup(r.text, "html.parser")
               
                # Try multiple selectors for GitHub description
                selectors = [
                    'meta[property="og:description"]',
                    'meta[name="description"]',
                    '.f4.my-3',
                    '.BorderGrid-cell .f4'
                ]
               
                for selector in selectors:
                    element = soup.select_one(selector)
                    if element:
                        content = element.get("content") if element.name == "meta" else element.get_text(strip=True)
                        if content and len(content.strip()) > 10:
                            app.logger.info(f"Found GitHub description: {content[:100]}...")
                            return content, url
                           
    except Exception:
        app.logger.exception("GitHub description fallback failed")
 
    return None, None
# ===================================================================================================================
def llm_resolve_domain(app_name: str) -> str:
    try:
        prompt = f"Return only the official primary website domain for '{app_name}'."
        resp = client.chat.completions.create(
            model=MODEL,
            temperature=0,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=100
        )
        text = resp.choices[0].message.content.strip().lower()
        if text.startswith("http"):
            text = text.split("//")[-1]
        return text.split("/")[0]
    except Exception:
        return ""

def validate_domain(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False

def resolve_application_domain(app_name: str) -> str:
    domain = llm_resolve_domain(app_name)
    if domain and validate_domain(domain):
        return domain
    key = app_name.replace(" ", "").lower()
    for tld in COMMON_TLDS:
        test_domain = key + tld
        if validate_domain(test_domain):
            return test_domain
    return "unknown"

# ============ FETCH METADATA ============
def fetch_app_metadata(app_name: str, domain: str):
    prompt = f"""
    Provide JSON with these keys for '{app_name}' ({domain}):
    - description
    - license
    - app_type
    - latest_version
    - release_date
    - support_status
    - official_link
    """
    try:
        resp = client.chat.completions.create(
            model=MODEL,
            temperature=0,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=250
        )
        text = resp.choices[0].message.content.strip()

        # Clean up markdown formatting if present
        if "```json" in text:
            text = text.replace("```json", "").replace("```", "").strip()

        parsed = json.loads(text)

        # Handle case where description contains embedded JSON
        if isinstance(parsed.get("description"), str):
            try:
                inner = json.loads(parsed["description"])
                parsed.update(inner)
            except:
                pass

        for field in ["license", "app_type", "latest_version", "release_date", "support_status", "official_link"]:
            parsed.setdefault(field, "unknown")

        return parsed

    except Exception as e:
        return {"error": str(e)}



# =========================================================
# ================== Security & Compliance ==================
def llm_resolve_domain(app_name: str) -> str:
    try:
        prompt = f"Give ONLY the official website domain for '{app_name}'"
        resp = client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": prompt}], max_tokens=20)
        candidate = resp.choices[0].message.content.strip().lower()
        if candidate.startswith("http"):
            candidate = candidate.split("//")[-1]
        return candidate.split("/")[0]
    except: return ""

def validate_domain(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return requests.get(f"https://{domain}", timeout=3).status_code < 500
    except: return False


def probe_ports(domain: str, ports=None):
    if ports is None: ports = [21,22,25,53,80,110,143,443,465,587,993,995,3306,3389,8080]
    results = {}
    def check_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.settimeout(0.5)
        try:
            if sock.connect_ex((domain, port)) == 0: return port
        finally: sock.close()
    with ThreadPoolExecutor(max_workers=30) as ex:
        for fut in as_completed([ex.submit(check_port, p) for p in ports]):
            port = fut.result()
            if port: results[port] = "open"
    return results

def check_ssl(domain: str) -> bool:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3); s.connect((domain, 443))
            return bool(s.getpeercert())
    except: return False

def llm_report(app_name, domain, summary, controls):
    prompt = f"Application: {app_name}\nDomain: {domain}\nSecurity Summary: {json.dumps(summary)}\nCompliance Controls: {json.dumps(controls)}"
    try:
        resp = client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": prompt}], max_tokens=400)
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return f"[LLM error: {e}]"



# =============================================================================================================




# =============================================================================================================

# ================== ROUTE ==================
@app.route("/", methods=["GET", "POST"])
def index():
    results = {}
    metadata = {}
    if request.method == "POST":
        app_name = request.form.get("app_name", "").strip()
        if app_name:
            # --- Version search ---
            search_query = f"{app_name} latest version release site:github.com OR changelog OR release notes"
            try: search_results = list(search(search_query, num_results=10))
            except: search_results = []
            version, date, source_url = None, None, None
            for url in search_results:
                v, d = extract_version_and_date(url)
                if v: version, date, source_url = v, d, url; break

            domain = resolve_application_domain(app_name)
            # --- Description ---
            description, description_url = fetch_app_description(app_name,search_results)

            # --- CVEs ---
            cve_list = search_vulnerabilities_nvd(app_name)
            if cve_list:
                severity, safe_to_install, breakdown = analyze_risk(cve_list)
                scores = [cve['cvss'] for cve in cve_list if isinstance(cve['cvss'], (int, float))]
                highest_score, avg_score = (max(scores), round(sum(scores)/len(scores),2)) if scores else ("N/A","N/A")
            else:
                severity, safe_to_install, highest_score, avg_score, breakdown = None, None, None, None, None

            # --- Security & Compliance ---
            
            summary, controls, report = {}, {}, None
            if domain != "unknown":
                ports = probe_ports(domain); ssl_ok = check_ssl(domain)
                summary = {"domain": domain, "ssl": "valid" if ssl_ok else "invalid", "open_ports": list(ports.keys())}
                controls = {
                    "ISO27001 – A.10.1 (Cryptographic Controls)": "Pass" if ssl_ok else "Fail",
                    "NIST 800-53 – SC-7 (Boundary Protection)": "Fail" if any(p in ports for p in RISKY_PORTS) else "Pass"
                }
                report = llm_report(app_name, domain, summary, controls)
                metadata = fetch_app_metadata(app_name, domain)

            results = {
                "app_name": app_name,
                "version": version, "date": date, "source_url": source_url,
                "description": description, "description_url": description_url,
                "cve_list": cve_list, "severity": severity, "safe_to_install": safe_to_install,
                "highest_score": highest_score, "avg_score": avg_score, "breakdown": breakdown,
                "security_summary": summary, "compliance": [{"standard": k, "status": v} for k,v in controls.items()],
                "security_analysis": report
            }
            # session['report_data'] = results
            # session['report_metadata'] = metadata

            # ✅ generate unique key
            report_id = str(uuid.uuid4())
            report_cache[report_id] = (results, metadata)

            # ✅ store only the small key in session
            session['report_id'] = report_id
            
    return render_template("index.html", results=results,metadata=metadata)
@app.route("/download_report", methods=["POST"])
def download_report():
    app_name = request.form.get("app_name")
    report_id = session.get("report_id")

    if not report_id or report_id not in report_cache:
        return "No report data available. Please analyze an app first.", 400

    results, metadata = report_cache[report_id]

    if not results or results.get("app_name") != app_name:
        return "No report data found for this application.", 400

    # ---- PDF Generation ----
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    x_margin, y_margin = 50, 50
    y = height - y_margin
    max_line_width = width

    def write_line(text, font="Helvetica", size=10, leading=14, bullet=False):
        nonlocal y
        p.setFont(font, size)
        max_chars = int(max_line_width / (size * 0.55))  # char width scaling
        lines = textwrap.wrap(text, width=max_chars) or [""]

        for i, line in enumerate(lines):
            if y < y_margin:
                p.showPage()
                y = height - y_margin
                p.setFont(font, size)

            prefix = "• " if bullet and i == 0 else "   " if bullet else ""
            p.drawString(x_margin, y, prefix + line)
            y -= leading

    def write_section(title, size=14):
        nonlocal y
        y -= 10  # spacing before section
        p.setFont("Helvetica-Bold", size)
        p.drawString(x_margin, y, title)
        y -= 6
        p.setLineWidth(0.5)
        p.line(x_margin, y, width - x_margin, y)
        y -= 14

    # ---- Header ----
    p.setTitle(f"{app_name} Security Report")
    p.setFont("Helvetica-Bold", 18)
    p.drawCentredString(width / 2, y, f"Security & Compliance Report: {app_name}")
    y -= 30
    p.setFont("Helvetica", 10)
    p.drawCentredString(width / 2, y, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 40

    # ---- Metadata ----
    write_section("Application Metadata")
    write_line(f"Version: {metadata.get('latest_version', 'N/A')}")
    write_line(f"Release Date: {metadata.get('release_date', 'N/A')}")
    write_line(f"Support Status: {metadata.get('support_status','N/A')}")
    write_line(f"App Type : {metadata.get('app_type','N/A')}")
    write_line(f"Official Source: {metadata.get('official_link', 'N/A')}")
    write_line(f"Description URL: {results.get('description_url', 'N/A')}")

    # ---- Description ----
    write_section("Description")
    desc = metadata.get("description") or "N/A"
    for line in desc.split("\n"):
        write_line(line.strip())

    # ---- CVE Summary ----
    write_section("CVE Summary")
    write_line(f"Severity: {results.get('severity')}")
    write_line(f"Safe to Install: {results.get('safe_to_install')}")
    write_line(f"Highest CVSS Score: {results.get('highest_score')}")
    write_line(f"Average CVSS Score: {results.get('avg_score')}")
    breakdown = results.get("breakdown", {})
    for k, v in breakdown.items():
        write_line(f"{k.capitalize()}: {v}")

    # ---- CVE List ----
    write_section("Top Vulnerabilities")
    cve_list = results.get("cve_list", [])[:10]
    if not cve_list:
        write_line("No known vulnerabilities found.")
    for cve in cve_list:
        write_line(f"{cve['id']}  (CVSS {cve['cvss']})", font="Helvetica-Bold", bullet=True)
        write_line(f"{cve['summary'][:200]}...", leading=12)

    # ---- Security ----
    write_section("Security Summary")
    sec = results.get("security_summary", {})
    for k, v in sec.items():
        write_line(f"{k}: {v}", bullet=True)

    # ---- Compliance ----
    write_section("Compliance Controls")
    for c in results.get("compliance", []):
        write_line(f"{c['standard']}: {c['status']}", bullet=True)

    # ---- LLM Report ----
    write_section("LLM Security Analysis")
    report = results.get("security_analysis") or "N/A"
    for line in report.split("\n"):
        write_line(line.strip())

    # ---- Additional Metadata ----
    # if metadata:
    #     write_section("Additional Metadata")
    #     for key, val in metadata.items():
    #         write_line(f"{key.replace('_', ' ').title()}: {val}", bullet=True)

    # ---- Footer with page numbers ----
    def add_page_number(canvas, doc):
        page_num = canvas.getPageNumber()
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(width - x_margin, 20, f"Page {page_num}")

    p.showPage()
    p.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"{app_name}_security_report.pdf",
        mimetype="application/pdf"
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))



