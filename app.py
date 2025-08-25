from flask import Flask, render_template, request
from googlesearch import search
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import quote
import time, os, socket, ssl, json
from datetime import datetime
from groq import Groq
from concurrent.futures import ThreadPoolExecutor, as_completed

# ======= CONFIG =======
NVD_API_KEY = os.getenv("NVD_API_KEY", "9d2ad8c1-bc76-409d-b97e-a9eedf2ae1a8")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "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")
MODEL = "moonshotai/kimi-k2-instruct"
DEFAULT_LOOKBACK_DAYS = int(os.getenv("DEFAULT_LOOKBACK_DAYS", 180))
# ======================

app = Flask(__name__)
client = Groq(api_key=GROQ_API_KEY)
COMMON_TLDS = [".com", ".org", ".net", ".ai", ".dev", ".io"]
RISKY_PORTS = [21, 23, 25, 110, 143, 3389]

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

def resolve_application_domain(app_name: str) -> str:
    domain = llm_resolve_domain(app_name)
    if domain and validate_domain(domain): return domain
    for tld in COMMON_TLDS:
        cand = app_name.replace(" ", "").lower() + tld
        if validate_domain(cand): return cand
    return "unknown"

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

# ================== ROUTE ==================
@app.route("/", methods=["GET", "POST"])
def index():
    results = {}
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
            domain = resolve_application_domain(app_name)
            summary, controls, report = {}, {}, None
            if domain != "unknown":
                ports = probe_ports(domain); ssl_ok = check_ssl(domain)
                summary = {"domain": domain, "ssl": "valid" if ssl_ok else "invalid", "open_ports": list(ports.keys())}
                controls = {
                    "ISO27001 – A.10.1 (Cryptographic Controls)": "Pass" if ssl_ok else "Fail",
                    "NIST 800-53 – SC-7 (Boundary Protection)": "Fail" if any(p in ports for p in RISKY_PORTS) else "Pass"
                }
                report = llm_report(app_name, domain, summary, controls)

            results = {
                "app_name": app_name,
                "version": version, "date": date, "source_url": source_url,
                "description": description, "description_url": description_url,
                "cve_list": cve_list, "severity": severity, "safe_to_install": safe_to_install,
                "highest_score": highest_score, "avg_score": avg_score, "breakdown": breakdown,
                "security_summary": summary, "compliance": [{"standard": k, "status": v} for k,v in controls.items()],
                "security_analysis": report
            }
    return render_template("index.html", results=results)

if __name__ == "__main__":
    app.run(debug=True, port=5080)
