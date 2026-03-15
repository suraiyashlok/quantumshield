from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import subprocess
import socket
import json
import threading
from datetime import datetime

app = Flask(__name__)
app.config["SECRET_KEY"] = "quantumshield2026"
CORS(app, origins="*", supports_credentials=True)
socketio = SocketIO(app, 
    cors_allowed_origins="*",
    async_mode="threading",
    logger=True,
    engineio_logger=True
)

# ─────────────────────────────────────────────
# FIPS STANDARDS
# ─────────────────────────────────────────────

FIPS_STANDARDS = {
    "FIPS 203": {
        "name": "ML-KEM (CRYSTALS-Kyber)",
        "function": "Key Encapsulation / Key Exchange",
        "algorithms": ["ML-KEM", "KYBER", "MLKEM", "X25519MLKEM"],
    },
    "FIPS 204": {
        "name": "ML-DSA (CRYSTALS-Dilithium)",
        "function": "Digital Signatures",
        "algorithms": ["ML-DSA", "DILITHIUM", "MLDSA"],
    },
    "FIPS 205": {
        "name": "SLH-DSA (SPHINCS+)",
        "function": "Hash-based Digital Signatures",
        "algorithms": ["SLH-DSA", "SPHINCS"],
    },
}

COMMON_BANK_SUBS = [
    "www", "retail", "netbanking", "api", "corp", "mobile",
    "internet", "online", "secure", "pay", "upi", "portal",
    "login", "app", "banking", "customer", "cards", "business"
]

# ─────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────

def is_live(hostname, port=443, timeout=3):
    try:
        ip = socket.gethostbyname(hostname)
        sock = socket.create_connection((hostname, port), timeout=timeout)
        sock.close()
        return True, ip
    except:
        return False, None


def extract_symmetric(cipher_name):
    c = cipher_name.upper()
    if "AES_256" in c or "AES-256" in c: return "AES-256"
    elif "AES_128" in c or "AES-128" in c: return "AES-128"
    elif "CHACHA20" in c: return "ChaCha20-256"
    elif "3DES" in c: return "3DES"
    return "Unknown"


def extract_hashing(cipher_name):
    c = cipher_name.upper()
    if "SHA384" in c: return "SHA-384"
    elif "SHA256" in c: return "SHA-256"
    elif "SHA" in c: return "SHA-1"
    return "Unknown"


def parse_sslyze_output(data, host):
    result = {
        "host": host,
        "tls_versions": [],
        "cipher_suites": [],
        "key_exchange": "Unknown",
        "authentication": "Unknown",
        "symmetric": "Unknown",
        "hashing": "Unknown",
        "cert_key_algo": "Unknown",
        "cert_key_size": 0,
        "cert_issuer": "Unknown",
        "cert_expiry": "Unknown",
        "cert_sig_algo": "Unknown",
        "pqc_algorithms": [],
        "vulnerabilities": []
    }
    try:
        scan_results = data.get("server_scan_results", [])
        if not scan_results:
            return result
        scan = scan_results[0]
        scan_result = scan.get("scan_result", {})

        tls_map = {
            "ssl_2_0_cipher_suites": "SSL 2.0",
            "ssl_3_0_cipher_suites": "SSL 3.0",
            "tls_1_0_cipher_suites": "TLS 1.0",
            "tls_1_1_cipher_suites": "TLS 1.1",
            "tls_1_2_cipher_suites": "TLS 1.2",
            "tls_1_3_cipher_suites": "TLS 1.3",
        }
        for key, label in tls_map.items():
            tls_data = scan_result.get(key, {})
            if tls_data and tls_data.get("status") == "COMPLETED":
                accepted = tls_data.get("result", {}).get("accepted_cipher_suites", [])
                if accepted:
                    result["tls_versions"].append(label)
                    if result["symmetric"] == "Unknown":
                        suite_name = accepted[0].get("cipher_suite", {}).get("name", "")
                        result["cipher_suites"].append(suite_name)
                        result["symmetric"] = extract_symmetric(suite_name)
                        result["hashing"] = extract_hashing(suite_name)
                        kex = accepted[0].get("ephemeral_key", {})
                        if kex:
                            result["key_exchange"] = kex.get("type_name", "Unknown")

        cert_info = scan_result.get("certificate_info", {})
        if cert_info and cert_info.get("status") == "COMPLETED":
            deployments = cert_info.get("result", {}).get("certificate_deployments", [])
            if deployments:
                chain = deployments[0].get("received_certificate_chain", [])
                if chain:
                    cert = chain[0]
                    pub_key = cert.get("public_key", {})
                    result["cert_key_algo"] = pub_key.get("algorithm", "Unknown")
                    result["cert_key_size"] = pub_key.get("key_size", 0)
                    result["authentication"] = pub_key.get("algorithm", "Unknown")
                    result["cert_sig_algo"] = cert.get("signature_hash_algorithm", {}).get("name", "Unknown")
                    result["cert_issuer"] = cert.get("issuer", {}).get("common_name", "Unknown")
                    not_after = cert.get("not_valid_after", "")
                    result["cert_expiry"] = not_after[:10] if not_after else "Unknown"

        pqc_keywords = ["ML-KEM", "ML-DSA", "KYBER", "DILITHIUM", "FALCON",
                        "SPHINCS", "X25519MLKEM", "MLKEM", "MLDSA"]
        all_text = json.dumps(data).upper()
        for kw in pqc_keywords:
            if kw in all_text:
                result["pqc_algorithms"].append(kw)

        if scan_result.get("heartbleed", {}).get("result", {}).get("is_vulnerable_to_heartbleed"):
            result["vulnerabilities"].append("Heartbleed")
        if scan_result.get("robot", {}).get("result", {}).get("robot_result", "") not in ["NOT_VULNERABLE", ""]:
            result["vulnerabilities"].append("ROBOT Attack")

    except Exception as e:
        print(f"Parse error: {e}")
    return result


def compute_qvs(scan):
    breakdown = {}
    kex = scan.get("key_exchange", "").upper()
    pqc_str = " ".join([p.upper() for p in scan.get("pqc_algorithms", [])])

    # Key Exchange (40 pts)
    if "ML-KEM" in kex or "KYBER" in kex or "MLKEM" in kex or "ML-KEM" in pqc_str:
        kex_score, kex_note = 0, "ML-KEM ✅ FIPS 203"
    elif "X25519MLKEM" in kex or "X25519MLKEM" in pqc_str:
        kex_score, kex_note = 10, "Hybrid PQC ⚠️"
    elif "X25519" in kex or "ECDH" in kex or "ECDHE" in kex:
        kex_score, kex_note = 25, "ECDHE/X25519 ❌ Shor's"
    elif "RSA" in kex:
        kex_score, kex_note = 40, "RSA ❌ Critical"
    else:
        kex_score, kex_note = 25, f"{scan.get('key_exchange','?')} ❓"
    breakdown["Key Exchange"] = {"score": kex_score, "max": 40, "weight": "40%", "note": kex_note}

    # Digital Signature (30 pts)
    auth = scan.get("authentication", "").upper()
    if "ML-DSA" in auth or "DILITHIUM" in auth or "ML-DSA" in pqc_str:
        sig_score, sig_note = 0, "ML-DSA ✅ FIPS 204"
    elif "SLH-DSA" in auth or "SPHINCS" in auth or "SLH-DSA" in pqc_str:
        sig_score, sig_note = 0, "SLH-DSA ✅ FIPS 205"
    elif "HYBRID" in auth:
        sig_score, sig_note = 10, "Hybrid PQC ⚠️"
    elif "EC" in auth or "ECDSA" in auth:
        sig_score, sig_note = 20, "ECDSA ❌ Shor's"
    elif "RSA" in auth:
        sig_score, sig_note = 30, "RSA ❌ Shor's"
    else:
        sig_score, sig_note = 20, f"{scan.get('authentication','?')} ❓"
    breakdown["Digital Signature"] = {"score": sig_score, "max": 30, "weight": "30%", "note": sig_note}

    # TLS Version (15 pts)
    versions = scan.get("tls_versions", [])
    if any(v in versions for v in ["SSL 2.0", "SSL 3.0", "TLS 1.0"]):
        tls_score, tls_note = 15, "Legacy TLS ❌ Critical"
    elif "TLS 1.1" in versions:
        tls_score, tls_note = 10, "TLS 1.1 ❌ Deprecated"
    elif "TLS 1.2" in versions and "TLS 1.3" not in versions:
        tls_score, tls_note = 5, "TLS 1.2 only ⚠️"
    elif "TLS 1.3" in versions and "TLS 1.2" not in versions:
        tls_score, tls_note = 0, "TLS 1.3 only ✅"
    else:
        tls_score, tls_note = 5, "TLS 1.2+1.3 ⚠️"
    breakdown["TLS Version"] = {"score": tls_score, "max": 15, "weight": "15%", "note": tls_note}

    # Cipher Suite (10 pts)
    sym = scan.get("symmetric", "").upper()
    if "AES-256" in sym or "CHACHA20" in sym:
        cipher_score, cipher_note = 0, f"{scan.get('symmetric')} ✅"
    elif "AES-128" in sym:
        cipher_score, cipher_note = 3, "AES-128 ⚠️ Grover's"
    elif "3DES" in sym or "RC4" in sym:
        cipher_score, cipher_note = 10, f"{scan.get('symmetric')} ❌ Broken"
    else:
        cipher_score, cipher_note = 5, f"{scan.get('symmetric','?')} ❓"
    breakdown["Cipher Suite"] = {"score": cipher_score, "max": 10, "weight": "10%", "note": cipher_note}

    # Certificate (5 pts)
    cert_algo = scan.get("cert_key_algo", "").upper()
    cert_size = scan.get("cert_key_size", 0)
    if "ML-DSA" in cert_algo or "SLH-DSA" in cert_algo:
        cert_score, cert_note = 0, "PQC Certificate ✅"
    elif "EC" in cert_algo:
        cert_score, cert_note = 2, f"ECC {cert_size}-bit ⚠️"
    elif "RSA" in cert_algo and cert_size >= 4096:
        cert_score, cert_note = 2, f"RSA-{cert_size} ⚠️"
    elif "RSA" in cert_algo:
        cert_score, cert_note = 3, f"RSA-{cert_size} ❌"
    else:
        cert_score, cert_note = 3, f"{scan.get('cert_key_algo','?')} ❓"
    breakdown["Certificate"] = {"score": cert_score, "max": 5, "weight": "5%", "note": cert_note}

    total = sum(v["score"] for v in breakdown.values())
    return total, breakdown


def get_label(score):
    if score <= 20:   return "Fully Quantum Safe"
    elif score <= 40: return "PQC Ready"
    elif score <= 70: return "Medium Quantum Risk"
    else:             return "High Quantum Risk"


def check_fips_compliance(scan):
    all_text = (
        scan.get("key_exchange", "") + " " +
        scan.get("authentication", "") + " " +
        " ".join(scan.get("pqc_algorithms", []))
    ).upper()
    compliance = {}
    for fips_id, info in FIPS_STANDARDS.items():
        compliance[fips_id] = any(alg in all_text for alg in info["algorithms"])
    return compliance


def get_recommendations(scan):
    recs = []
    auth = scan.get("authentication", "").upper()
    kex = scan.get("key_exchange", "").upper()
    sym = scan.get("symmetric", "").upper()
    versions = scan.get("tls_versions", [])
    if "ML-DSA" not in auth:
        recs.append({"priority": "critical", "action": "Replace certificate algorithm with ML-DSA-65 (FIPS 204)"})
    if "ML-KEM" not in kex and "KYBER" not in kex:
        recs.append({"priority": "critical", "action": "Replace key exchange with ML-KEM-768 (FIPS 203)"})
    if any(v in versions for v in ["TLS 1.0", "TLS 1.1", "SSL 2.0", "SSL 3.0"]):
        recs.append({"priority": "high", "action": "Disable legacy TLS versions (1.0, 1.1, SSL 2.0/3.0) immediately"})
    if "AES-128" in sym:
        recs.append({"priority": "medium", "action": "Upgrade AES-128 to AES-256 for stronger symmetric encryption"})
    if "3DES" in sym:
        recs.append({"priority": "critical", "action": "Remove 3DES cipher suites immediately"})
    if "TLS 1.3" not in versions:
        recs.append({"priority": "high", "action": "Enable TLS 1.3 as the preferred protocol"})
    if not recs:
        recs.append({"priority": "info", "action": "No immediate actions required — maintain PQC readiness"})
    return recs


def get_migration_roadmap():
    return [
        {
            "phase": 1,
            "title": "Immediate Actions",
            "timeframe": "0–3 months",
            "effort": "Low",
            "risk": "Low",
            "tasks": [
                "Disable TLS 1.0 and TLS 1.1",
                "Remove 3DES cipher suites",
                "Enable TLS 1.3 as preferred protocol",
                "Upgrade AES-128 to AES-256 everywhere"
            ]
        },
        {
            "phase": 2,
            "title": "Hybrid PQC Deployment",
            "timeframe": "3–6 months",
            "effort": "Medium",
            "risk": "Medium",
            "tasks": [
                "Deploy hybrid certificates (RSA + ML-DSA)",
                "Enable X25519MLKEM768 for key exchange",
                "Test on staging environment",
                "Update load balancer configurations"
            ]
        },
        {
            "phase": 3,
            "title": "Full PQC Migration",
            "timeframe": "6–18 months",
            "effort": "High",
            "risk": "High",
            "tasks": [
                "Replace RSA certificates with ML-DSA-65 (FIPS 204)",
                "Set ML-KEM-768 as primary key exchange (FIPS 203)",
                "Update all internal API-to-API TLS calls",
                "Migrate ATM network key exchange to ML-KEM"
            ]
        },
        {
            "phase": 4,
            "title": "Certification",
            "timeframe": "18–24 months",
            "effort": "Medium",
            "risk": "Low",
            "tasks": [
                "Third-party PQC audit",
                "Apply for NIST PQC Ready certification",
                "Issue digital Quantum-Safe certificate/label",
                "Schedule annual PQC review"
            ]
        }
    ]


# ─────────────────────────────────────────────
# SCAN WORKER (runs in background thread)
# ─────────────────────────────────────────────

def run_scan(domain, sid):
    """Full scan pipeline — emits progress to frontend via SocketIO"""

    def emit_progress(step, message, data=None):
        socketio.emit("scan_progress", {
            "step": step,
            "message": message,
            "data": data or {}
        }, room=sid)

    try:
        # Step 1: Discover subdomains
        emit_progress("discovery", f"Discovering subdomains for {domain}...")
        subdomains = []
        try:
            result = subprocess.run(
                ["subfinder", "-d", domain, "-silent", "-max-time", "20"],
                capture_output=True, text=True, timeout=25
            )
            if result.stdout:
                subdomains = [s.strip() for s in result.stdout.splitlines() if s.strip()]
        except:
            pass

        if not subdomains:
            subdomains = [f"{sub}.{domain}" for sub in COMMON_BANK_SUBS]
            subdomains.append(domain)

        emit_progress("discovery", f"Found {len(subdomains)} candidate subdomains",
                      {"subdomains": subdomains[:20]})

        # Step 2: Filter live hosts
        emit_progress("connectivity", "Checking which hosts are live on port 443...")
        live_hosts = []
        for sub in subdomains[:20]:
            alive, ip = is_live(sub)
            if alive:
                live_hosts.append({"host": sub, "ip": ip})
                emit_progress("connectivity", f"Live: {sub}",
                              {"host": sub, "ip": ip, "status": "live"})
            else:
                emit_progress("connectivity", f"Unreachable: {sub}",
                              {"host": sub, "status": "dead"})

        if not live_hosts:
            socketio.emit("scan_error", {"message": "No live hosts found."}, room=sid)
            return

        emit_progress("connectivity", f"{len(live_hosts)} live hosts found",
                      {"total_live": len(live_hosts)})

        # Step 3: TLS Scan each host
        all_results = []
        for i, host_info in enumerate(live_hosts):
            host = host_info["host"]
            ip = host_info["ip"]

            emit_progress("scanning", f"Scanning TLS for {host} ({i+1}/{len(live_hosts)})...",
                          {"host": host, "current": i+1, "total": len(live_hosts)})

            try:
                proc = subprocess.run(
                    ["python", "-m", "sslyze", "--json_out=-", host],
                    capture_output=True, text=True, timeout=60
                )
                if not proc.stdout:
                    continue
                data = json.loads(proc.stdout)
                scan = parse_sslyze_output(data, host)
            except Exception as e:
                emit_progress("scanning", f"Failed: {host} — {str(e)}")
                continue

            score, breakdown = compute_qvs(scan)
            label = get_label(score)
            fips = check_fips_compliance(scan)
            recs = get_recommendations(scan)
            roadmap = get_migration_roadmap()

            asset_result = {
                "host": host,
                "ip": ip,
                "scan": scan,
                "score": score,
                "label": label,
                "breakdown": breakdown,
                "fips_compliance": fips,
                "recommendations": recs,
                "migration_roadmap": roadmap
            }

            all_results.append(asset_result)

            # Emit this asset's result immediately
            emit_progress("result", f"Scanned: {host}", {"asset": asset_result})

        # Step 4: Final summary
        cbom = {
            "scan_date": datetime.now().isoformat(),
            "target_domain": domain,
            "total_assets": len(all_results),
            "scoring_model": {
                "weights": {
                    "key_exchange": "40%",
                    "digital_signature": "30%",
                    "tls_version": "15%",
                    "cipher_suite": "10%",
                    "certificate": "5%"
                },
                "classification": {
                    "0-20": "Fully Quantum Safe",
                    "21-40": "PQC Ready",
                    "41-70": "Medium Quantum Risk",
                    "71-100": "High Quantum Risk"
                }
            },
            "assets": all_results
        }

        socketio.emit("scan_complete", {"cbom": cbom}, room=sid)

    except Exception as e:
        socketio.emit("scan_error", {"message": str(e)}, room=sid)


# ─────────────────────────────────────────────
# SOCKET EVENTS
# ─────────────────────────────────────────────

@socketio.on("start_scan")
def handle_scan(data):
    domain = data.get("domain", "").strip()
    if not domain:
        emit("scan_error", {"message": "No domain provided"})
        return
    sid = request.sid
    thread = threading.Thread(target=run_scan, args=(domain, sid))
    thread.daemon = True
    thread.start()


@socketio.on("connect")
def handle_connect():
    print(f"Client connected: {request.sid}")


@socketio.on("disconnect")
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")


# ─────────────────────────────────────────────
# REST ENDPOINTS
# ─────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "QuantumShield API"})


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
