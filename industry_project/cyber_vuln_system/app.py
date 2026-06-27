from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import uuid

# Try to set the custom Git executable if it exists; otherwise fallback to system Git
custom_git_path = "D:\\hive\\git\\Git\\bin\\git.exe"
default_git_path = "C:\\Program Files\\Git\\bin\\git.exe"
if os.path.exists(custom_git_path):
    os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = custom_git_path
elif os.path.exists(default_git_path):
    os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = default_git_path
try:
    import git
    GIT_AVAILABLE = True
except Exception as e:
    print(f"[!] Warning: GitPython or Git executable not found. GitHub repo scanning will be disabled. Error: {e}")
    GIT_AVAILABLE = False
import shutil
import stat
from dotenv import load_dotenv

# Import your modules
from modules.static_scanner import StaticVulnerabilityScanner
from modules.ai_analyzer import AISecurityAnalyzer
from modules.risk_classifier import RiskClassifier
from profile.code_generator import SecureCodeGenerator
from profile.report_generator import ReportGenerator

# Import new modules
from database import init_db
from modules.auth import create_default_admin
from api_routes import api
from realtime import init_socketio

load_dotenv()

app = Flask(__name__)

# ── New: CORS for Flutter app ──
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ── New: Initialize database and default admin ──
init_db()
create_default_admin()

# ── New: Register API v2 blueprint ──
app.register_blueprint(api)

# ── New: Initialize WebSocket support ──
socketio = init_socketio(app)

# Essential Directories
os.makedirs("sample_code", exist_ok=True)
reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "reports"))
os.makedirs(reports_dir, exist_ok=True)

# Pipeline Setup
scanner = StaticVulnerabilityScanner()
analyzer = AISecurityAnalyzer()
classifier = RiskClassifier()

def detect_language(code):
    """Automatic Language Detection based on syntax markers."""
    snippet = code.strip()[:500]
    if "#include" in snippet or "int main(" in snippet: return "cpp"
    if "const " in snippet or "let " in snippet: return "javascript"
    return "python"

def run_full_analysis(source_code, file_path, language):
    """Helper to run the full security pipeline."""
    raw_vulns, _, _ = scanner.scan_file(file_path, language=language)
    ai_res = analyzer.analyze(source_code, file_path, language, raw_vulns)
    risk_p = classifier.classify(ai_res, file_path, language)
    reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "reports"))
    try:
        remediation = SecureCodeGenerator(output_dir=reports_dir).generate(source_code, risk_p)
    except:
        remediation = None
        
    full_report_path = ReportGenerator(output_dir=reports_dir).generate_html_report(risk_p, remediation, source_code)
    web_report_path = f"reports/{os.path.basename(full_report_path)}"
    return {
        "risk_score": risk_p.risk_score,
        "risk_level": risk_p.risk_level,
        "vulnerabilities": [v.__dict__ for v in ai_res.analyzed_vulnerabilities],
        "report_path": web_report_path
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    # 1. UNIVERSAL DATA CAPTURE
    if request.is_json:
        data = request.json
    else:
        data = request.form
    
    mode = data.get('mode')
    print(f"[*] Analysis Request Received - Mode: {mode}")

    try:
        # --- MODE: PASTE ---
        if mode == 'paste':
            source_code = data.get('code', '')
            lang = detect_language(source_code)
            temp_path = os.path.join("sample_code", f"paste_{uuid.uuid4().hex[:6]}.py")
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(source_code)
            return jsonify(run_full_analysis(source_code, temp_path, lang))

        # --- MODE: GITHUB ---
        elif mode == 'github':
            repo_url = data.get('github_url') or data.get('repo_url')
            if not repo_url:
                return jsonify({"error": "Missing GitHub URL"}), 400
                
            repo_dir = os.path.abspath(os.path.join("sample_code", f"repo_{uuid.uuid4().hex[:6]}"))
            print(f"[*] Cloning repository: {repo_url}")
            git.Repo.clone_from(repo_url, repo_dir)
            
            all_vulnerabilities = []
            max_risk_score = 0
            overall_risk_level = "Low"
            final_report_path = ""
            files_scanned = 0
            
            for root, _, files in os.walk(repo_dir):
                for file_name in files:
                    if file_name.endswith(('.py', '.js', '.cpp')):
                        f_path = os.path.join(root, file_name)
                        with open(f_path, "r", encoding="utf-8", errors="ignore") as f:
                            code = f.read()
                        
                        try:
                            res = run_full_analysis(code, f_path, detect_language(code))
                            
                            # Prefix category with filename for context in the frontend
                            for v in res.get("vulnerabilities", []):
                                v["category"] = f"[{file_name}] {v.get('category', 'Unknown')}"
                            
                            all_vulnerabilities.extend(res.get("vulnerabilities", []))
                            
                            if res.get("risk_score", 0) >= max_risk_score:
                                max_risk_score = res.get("risk_score", 0)
                                overall_risk_level = res.get("risk_level", "Low")
                                final_report_path = res.get("report_path", "")
                                
                            files_scanned += 1
                        except Exception as e:
                            print(f"[!] Error analyzing {file_name}: {e}")
            
            if files_scanned == 0:
                return jsonify({"error": "No supported files found in repository"}), 400
                
            return jsonify({
                "risk_score": max_risk_score,
                "risk_level": overall_risk_level,
                "vulnerabilities": all_vulnerabilities,
                "report_path": final_report_path
            })

        # --- MODE: UPLOAD ---
        elif mode == 'upload':
            file = request.files.get('file')
            if not file:
                return jsonify({"error": "No file uploaded"}), 400
            
            t_path = os.path.abspath(os.path.join("sample_code", f"up_{uuid.uuid4().hex[:6]}_{file.filename}"))
            file.save(t_path)
            
            with open(t_path, "r", encoding="utf-8", errors="ignore") as f:
                source_code = f.read()
            
            lang = detect_language(source_code)
            return jsonify(run_full_analysis(source_code, t_path, lang))

        # --- SAFETY FALLBACK ---
        else:
            return jsonify({"error": f"Invalid mode: {mode}"}), 400

    except Exception as e:
        print(f"[!] SYSTEM CRASH: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/reports/<path:path>')
def send_report(path):
    reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "reports"))
    return send_from_directory(reports_dir, path)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"\n[+] AI Cyber Shield Web Portal: http://0.0.0.0:{port}")
    print(f"[+] API v2 Endpoints:           http://0.0.0.0:{port}/api/v2/")
    print(f"[+] WebSocket:                  ws://0.0.0.0:{port}")
    print("[+] Default admin login:        admin / admin123\n")
    socketio.run(app, debug=False, host="0.0.0.0", port=port, allow_unsafe_werkzeug=True)