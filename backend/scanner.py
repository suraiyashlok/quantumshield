import subprocess
import json
import socket
import sys
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

console = Console()

# ─────────────────────────────────────────────
# STEP 1: SUBDOMAIN DISCOVERY
# ─────────────────────────────────────────────

def discover_subdomains(domain, max_results=20):
    """Use subfinder to discover subdomains"""
    console.print(f"\n[cyan]🔍 Discovering subdomains for {domain}...[/cyan]")
    
    # Common bank subdomains as fallback
    common_subs = [
        "www", "retail", "netbanking", "api", "corp", "mobile",
        "internet", "online", "secure", "pay", "upi", "portal",
        "login", "app", "banking", "customer", "cards"
    ]
    
    subdomains = []
    
    # Try subfinder first
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-max-time", "30"],
            capture_output=True, text=True, timeout=35
        )
        if result.stdout:
            subdomains = [s.strip() for s in result.stdout.splitlines() if s.strip()]
            console.print(f"[green]✅ subfinder found {len(subdomains)} subdomains[/green]")
    except Exception as e:
        console.print(f"[yellow]⚠️  subfinder timed out, using common subdomain list[/yellow]")

    # If subfinder found nothing, use common subdomains
    if not subdomains:
        subdomains = [f"{sub}.{domain}" for sub in common_subs]
        subdomains.append(domain)  # include root domain

    # Limit results
    return subdomains[:max_results]


# ─────────────────────────────────────────────
# STEP 2: CHECK WHICH SUBDOMAINS ARE LIVE
# ─────────────────────────────────────────────

def is_live(hostname, port=443, timeout=3):
    """Check if a host is reachable on port 443"""
    try:
        ip = socket.gethostbyname(hostname)
        sock = socket.create_connection((hostname, port), timeout=timeout)
        sock.close()
        return True, ip
    except socket.gaierror:
        return False, None  # DNS failed
    except Exception:
        return False, None


def filter_live_hosts(subdomains):
    """Filter only live HTTPS hosts"""
    console.print(f"\n[cyan]🌐 Checking which hosts are live on port 443...[/cyan]")
    live = []
    for sub in subdomains:
        alive, ip = is_live(sub)
        if alive:
            live.append({"host": sub, "ip": ip})
            console.print(f"  [green]✅ {sub} → {ip}[/green]")
        else:
            console.print(f"  [red]❌ {sub} → unreachable[/red]")
    console.print(f"\n[green]Found {len(live)} live hosts[/green]")
    return live


# ─────────────────────────────────────────────
# STEP 3: TLS SCANNING WITH SSLYZE
# ─────────────────────────────────────────────

def scan_tls(host):
    """Run sslyze on a host and parse results"""
    console.print(f"\n[cyan]🔐 Scanning TLS for {host}...[/cyan]")
    try:
        result = subprocess.run(
            ["python", "-m", "sslyze", "--json_out=-", host],
            capture_output=True, text=True, timeout=60
        )
        if result.stdout:
            data = json.loads(result.stdout)
            return parse_sslyze_output(data, host)
    except subprocess.TimeoutExpired:
        console.print(f"  [yellow]⚠️  Scan timed out for {host}[/yellow]")
    except Exception as e:
        console.print(f"  [red]❌ Scan failed for {host}: {e}[/red]")
    return None


def parse_sslyze_output(data, host):
    """Extract crypto details from sslyze JSON output"""
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

        # TLS Versions
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
                    # Extract cipher details from first accepted suite
                    if result["symmetric"] == "Unknown":
                        suite_name = accepted[0].get("cipher_suite", {}).get("name", "")
                        result["cipher_suites"].append(suite_name)
                        result["symmetric"] = extract_symmetric(suite_name)
                        result["hashing"] = extract_hashing(suite_name)
                        kex = accepted[0].get("ephemeral_key", {})
                        if kex:
                            result["key_exchange"] = kex.get("type_name", "Unknown")

        # Certificate Info
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

        # PQC Detection
        pqc_keywords = ["ML-KEM", "ML-DSA", "KYBER", "DILITHIUM", "FALCON",
                        "SPHINCS", "X25519MLKEM", "MLKEM", "MLDSA"]
        all_text = json.dumps(data).upper()
        for kw in pqc_keywords:
            if kw in all_text:
                result["pqc_algorithms"].append(kw)

        # Known vulnerabilities
        if scan_result.get("heartbleed", {}).get("result", {}).get("is_vulnerable_to_heartbleed"):
            result["vulnerabilities"].append("Heartbleed")
        if scan_result.get("robot", {}).get("result", {}).get("robot_result", "") not in ["NOT_VULNERABLE", ""]:
            result["vulnerabilities"].append("ROBOT Attack")

    except Exception as e:
        console.print(f"  [red]Parse error: {e}[/red]")

    return result


def extract_symmetric(cipher_name):
    cipher_name = cipher_name.upper()
    if "AES_256" in cipher_name or "AES-256" in cipher_name:
        return "AES-256"
    elif "AES_128" in cipher_name or "AES-128" in cipher_name:
        return "AES-128"
    elif "CHACHA20" in cipher_name:
        return "ChaCha20-256"
    elif "3DES" in cipher_name:
        return "3DES"
    return "Unknown"


def extract_hashing(cipher_name):
    cipher_name = cipher_name.upper()
    if "SHA384" in cipher_name:
        return "SHA-384"
    elif "SHA256" in cipher_name:
        return "SHA-256"
    elif "SHA" in cipher_name:
        return "SHA-1"
    return "Unknown"


# ─────────────────────────────────────────────
# STEP 4: VULNERABILITY SCORING (NIST-Aligned)
# ─────────────────────────────────────────────
#
# Weighted model (higher score = higher risk):
#   Key Exchange Algorithm  : 40 pts
#   Digital Signature       : 30 pts
#   TLS Protocol Version    : 15 pts
#   Cipher Suite Strength   : 10 pts
#   Certificate Parameters  :  5 pts
#   TOTAL                   : 100 pts
#
# FIPS Compliance checked against:
#   FIPS 203 → ML-KEM  (key exchange)
#   FIPS 204 → ML-DSA  (digital signatures)
#   FIPS 205 → SLH-DSA (hash-based signatures)

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


def check_fips_compliance(scan):
    """
    Check compliance against FIPS 203, 204, 205.
    Returns dict: { "FIPS 203": True/False, "FIPS 204": True/False, "FIPS 205": True/False }
    """
    all_text = (
        scan.get("key_exchange", "") + " " +
        scan.get("authentication", "") + " " +
        " ".join(scan.get("pqc_algorithms", []))
    ).upper()

    compliance = {}
    for fips_id, info in FIPS_STANDARDS.items():
        compliant = any(alg in all_text for alg in info["algorithms"])
        compliance[fips_id] = compliant
    return compliance


def compute_qvs(scan):
    """
    Compute Quantum Risk Score (0-100).
    Higher score = higher quantum risk.

    Component weights (bank-focused, quantum-threat-prioritized):
      Key Exchange Algorithm : 40 pts
      Digital Signature      : 30 pts
      TLS Protocol Version   : 15 pts
      Cipher Suite Strength  : 10 pts
      Certificate Parameters :  5 pts
    """
    breakdown = {}

    # ── KEY EXCHANGE (40 pts) ──────────────────
    # Determines long-term secrecy of all session data
    kex = scan.get("key_exchange", "").upper()
    pqc = [p.upper() for p in scan.get("pqc_algorithms", [])]
    pqc_str = " ".join(pqc)

    if "ML-KEM" in kex or "KYBER" in kex or "MLKEM" in kex or "ML-KEM" in pqc_str:
        kex_score = 0       # FIPS 203 compliant — fully safe
        kex_note = "ML-KEM ✅ FIPS 203"
    elif "X25519MLKEM" in kex or "X25519MLKEM" in pqc_str:
        kex_score = 10      # Hybrid PQC — transitional
        kex_note = "Hybrid PQC (X25519+MLKEM) ⚠️"
    elif "X25519" in kex or "ECDH" in kex or "ECDHE" in kex:
        kex_score = 25      # Classical ECC — Shor's vulnerable
        kex_note = "ECDHE/X25519 ❌ Shor's vulnerable"
    elif "RSA" in kex:
        kex_score = 40      # RSA key exchange — worst case
        kex_note = "RSA ❌ Critically vulnerable"
    else:
        kex_score = 25      # Unknown — assume classical
        kex_note = f"{scan.get('key_exchange','Unknown')} ❓ Unverified"
    breakdown["Key Exchange (40%)"] = {"score": kex_score, "max": 40, "note": kex_note}

    # ── DIGITAL SIGNATURE (30 pts) ────────────
    # Determines server identity trust
    auth = scan.get("authentication", "").upper()

    if "ML-DSA" in auth or "DILITHIUM" in auth or "ML-DSA" in pqc_str:
        sig_score = 0       # FIPS 204 compliant
        sig_note = "ML-DSA ✅ FIPS 204"
    elif "SLH-DSA" in auth or "SPHINCS" in auth or "SLH-DSA" in pqc_str:
        sig_score = 0       # FIPS 205 compliant
        sig_note = "SLH-DSA ✅ FIPS 205"
    elif "HYBRID" in auth:
        sig_score = 10      # Hybrid PQC
        sig_note = "Hybrid PQC signature ⚠️"
    elif "EC" in auth or "ECDSA" in auth:
        sig_score = 20      # ECC — Shor's vulnerable
        sig_note = "ECDSA ❌ Shor's vulnerable"
    elif "RSA" in auth:
        sig_score = 30      # RSA — worst case
        sig_note = "RSA ❌ Shor's vulnerable"
    else:
        sig_score = 20
        sig_note = f"{scan.get('authentication','Unknown')} ❓ Unverified"
    breakdown["Digital Signature (30%)"] = {"score": sig_score, "max": 30, "note": sig_note}

    # ── TLS PROTOCOL VERSION (15 pts) ─────────
    # Affects overall protocol security posture
    versions = scan.get("tls_versions", [])
    worst_version = ""
    if any(v in versions for v in ["SSL 2.0", "SSL 3.0"]):
        tls_score = 15
        worst_version = "SSL 2.0/3.0 ❌ Critically outdated"
    elif "TLS 1.0" in versions:
        tls_score = 15
        worst_version = "TLS 1.0 ❌ Deprecated"
    elif "TLS 1.1" in versions:
        tls_score = 10
        worst_version = "TLS 1.1 ❌ Deprecated"
    elif "TLS 1.2" in versions and "TLS 1.3" not in versions:
        tls_score = 5
        worst_version = "TLS 1.2 only ⚠️"
    elif "TLS 1.3" in versions and "TLS 1.2" not in versions:
        tls_score = 0
        worst_version = "TLS 1.3 only ✅"
    else:
        tls_score = 5       # Both 1.2 and 1.3
        worst_version = "TLS 1.2 + 1.3 ⚠️ Disable 1.2"
    breakdown["TLS Version (15%)"] = {"score": tls_score, "max": 15, "note": worst_version}

    # ── CIPHER SUITE STRENGTH (10 pts) ────────
    # Symmetric encryption — less quantum risk but operationally important
    sym = scan.get("symmetric", "").upper()
    if "AES-256" in sym or "CHACHA20" in sym:
        cipher_score = 0
        cipher_note = f"{scan.get('symmetric')} ✅ Quantum resistant"
    elif "AES-128" in sym:
        cipher_score = 3
        cipher_note = "AES-128 ⚠️ Grover's halves security"
    elif "3DES" in sym or "RC4" in sym:
        cipher_score = 10
        cipher_note = f"{scan.get('symmetric')} ❌ Classically weak"
    else:
        cipher_score = 5
        cipher_note = f"{scan.get('symmetric','Unknown')} ❓ Unverified"
    breakdown["Cipher Suite (10%)"] = {"score": cipher_score, "max": 10, "note": cipher_note}

    # ── CERTIFICATE PARAMETERS (5 pts) ────────
    # Certificate quality and key size
    cert_algo = scan.get("cert_key_algo", "").upper()
    cert_size = scan.get("cert_key_size", 0)

    if "ML-DSA" in cert_algo or "SLH-DSA" in cert_algo:
        cert_score = 0
        cert_note = "PQC Certificate ✅"
    elif "EC" in cert_algo:
        cert_score = 2
        cert_note = f"ECC {cert_size}-bit ⚠️ Shor's vulnerable"
    elif "RSA" in cert_algo and cert_size >= 4096:
        cert_score = 2
        cert_note = f"RSA-{cert_size} ⚠️ Large but still vulnerable"
    elif "RSA" in cert_algo and cert_size >= 2048:
        cert_score = 3
        cert_note = f"RSA-{cert_size} ❌ Standard but quantum vulnerable"
    elif "RSA" in cert_algo:
        cert_score = 5
        cert_note = f"RSA-{cert_size} ❌ Weak key size"
    else:
        cert_score = 3
        cert_note = f"{scan.get('cert_key_algo','Unknown')} ❓ Unverified"
    breakdown["Certificate (5%)"] = {"score": cert_score, "max": 5, "note": cert_note}

    # ── TOTAL RISK SCORE ──────────────────────
    total = sum(v["score"] for v in breakdown.values())

    return total, breakdown


def get_label(score):
    """
    Risk classification based on weighted score (higher = more risk):
      0–20  : Fully Quantum Safe
      21–40 : PQC Ready
      41–70 : Medium Quantum Risk
      71–100: High Quantum Risk
    """
    if score <= 20:
        return "✅ FULLY QUANTUM SAFE"
    elif score <= 40:
        return "🟢 PQC READY"
    elif score <= 70:
        return "🟡 MEDIUM QUANTUM RISK"
    else:
        return "🔴 HIGH QUANTUM RISK"


# ─────────────────────────────────────────────
# STEP 5: RECOMMENDATIONS
# ─────────────────────────────────────────────

def get_recommendations(scan):
    recs = []
    auth = scan.get("authentication", "").upper()
    kex = scan.get("key_exchange", "").upper()
    sym = scan.get("symmetric", "").upper()
    versions = scan.get("tls_versions", [])

    if "ML-DSA" not in auth:
        recs.append("🔴 Replace certificate algorithm with ML-DSA-65 (FIPS 204)")
    if "ML-KEM" not in kex and "KYBER" not in kex:
        recs.append("🔴 Replace key exchange with ML-KEM-768 (FIPS 203)")
    if any(v in versions for v in ["TLS 1.0", "TLS 1.1"]):
        recs.append("🟠 Disable TLS 1.0 and TLS 1.1 immediately")
    if any(v in versions for v in ["SSL 2.0", "SSL 3.0"]):
        recs.append("🔴 Disable SSL 2.0 and SSL 3.0 immediately")
    if "AES-128" in sym:
        recs.append("🟡 Upgrade AES-128 to AES-256 for stronger symmetric encryption")
    if "3DES" in sym:
        recs.append("🔴 Remove 3DES cipher suites immediately")
    if "TLS 1.3" not in versions:
        recs.append("🟠 Enable TLS 1.3 as the preferred protocol")

    if not recs:
        recs.append("✅ No immediate actions required — maintain PQC readiness")

    return recs


def get_migration_roadmap(score):
    if score > 90:
        return "Asset is PQC Ready. Schedule annual review."
    roadmap = []
    roadmap.append("PHASE 1 (0-3 months): Disable TLS 1.0/1.1, remove 3DES, enable TLS 1.3")
    roadmap.append("PHASE 2 (3-6 months): Deploy hybrid certificates (RSA + ML-DSA), enable X25519MLKEM768")
    roadmap.append("PHASE 3 (6-18 months): Full migration to ML-DSA-65 + ML-KEM-768")
    roadmap.append("PHASE 4 (18-24 months): Third-party PQC audit + apply for PQC Ready certification")
    return "\n".join(roadmap)


# ─────────────────────────────────────────────
# STEP 6: DISPLAY RESULTS
# ─────────────────────────────────────────────

def display_asset_result(scan, score, breakdown, label, recs):
    host = scan["host"]

    console.print(f"\n{'═'*80}")
    console.print(f"[bold cyan]  ASSET: {host}[/bold cyan]")
    console.print(f"{'═'*80}")

    # ── 1. CRYPTOGRAPHIC STACK TABLE ──────────
    stack_table = Table(
        title=f"Cryptographic Stack Analysis",
        show_header=True, header_style="bold cyan",
        border_style="cyan"
    )
    stack_table.add_column("Component", style="bold white", width=22)
    stack_table.add_column("Weight", width=8)
    stack_table.add_column("Detected Algorithm", width=28)
    stack_table.add_column("Quantum Threat", width=22)
    stack_table.add_column("NIST PQC Standard", width=18)
    stack_table.add_column("Recommended", style="green", width=18)

    kex_safe = any(k in scan.get("key_exchange","").upper() for k in ["ML-KEM","KYBER","MLKEM"])
    sig_safe = any(k in scan.get("authentication","").upper() for k in ["ML-DSA","DILITHIUM","SLH-DSA","SPHINCS"])

    stack_table.add_row(
        "Key Exchange", "40%",
        scan["key_exchange"],
        "[green]None ✅[/green]" if kex_safe else "[red]Shor's Algo ❌[/red]",
        "[green]FIPS 203 ✅[/green]" if kex_safe else "[red]Not Compliant[/red]",
        "ML-KEM-768"
    )
    stack_table.add_row(
        "Digital Signature", "30%",
        f"{scan['cert_key_algo']} {scan['cert_key_size']}",
        "[green]None ✅[/green]" if sig_safe else "[red]Shor's Algo ❌[/red]",
        "[green]FIPS 204 ✅[/green]" if sig_safe else "[red]Not Compliant[/red]",
        "ML-DSA-65"
    )
    stack_table.add_row(
        "TLS Version", "15%",
        ", ".join(scan["tls_versions"]) if scan["tls_versions"] else "Unknown",
        "[red]Downgrade risk ❌[/red]" if any(v in scan["tls_versions"] for v in ["TLS 1.0","TLS 1.1"]) else "[green]OK ✅[/green]",
        "N/A",
        "TLS 1.3 only"
    )
    stack_table.add_row(
        "Cipher Suite", "10%",
        scan["symmetric"],
        "[yellow]Grover's ⚠️[/yellow]" if "AES" in scan["symmetric"].upper() else "[red]Broken ❌[/red]",
        "N/A",
        "AES-256-GCM"
    )
    stack_table.add_row(
        "Certificate", "5%",
        f"{scan['cert_key_algo']} {scan['cert_key_size']} bits",
        "[green]None ✅[/green]" if sig_safe else "[red]Shor's Algo ❌[/red]",
        "[green]FIPS 204/205 ✅[/green]" if sig_safe else "[red]Not Compliant[/red]",
        "ML-DSA cert"
    )
    console.print(stack_table)

    # ── 2. FIPS COMPLIANCE TABLE ───────────────
    fips = check_fips_compliance(scan)
    fips_table = Table(
        title="NIST FIPS Post-Quantum Compliance",
        show_header=True, header_style="bold magenta",
        border_style="magenta"
    )
    fips_table.add_column("Standard", width=12)
    fips_table.add_column("Algorithm", width=28)
    fips_table.add_column("Function", width=30)
    fips_table.add_column("Status", width=20)

    for fips_id, compliant in fips.items():
        info = FIPS_STANDARDS[fips_id]
        fips_table.add_row(
            f"[bold]{fips_id}[/bold]",
            info["name"],
            info["function"],
            "[green]✅ COMPLIANT[/green]" if compliant else "[red]❌ NOT COMPLIANT[/red]"
        )
    console.print(fips_table)

    # ── 3. WEIGHTED RISK SCORE BREAKDOWN ──────
    color = "green" if score <= 20 else "green" if score <= 40 else "yellow" if score <= 70 else "red"

    score_lines = []
    for component, data in breakdown.items():
        s = data["score"]
        m = data["max"]
        note = data["note"]
        bar_filled = int((s / m) * 10) if m > 0 else 0
        bar = "█" * bar_filled + "░" * (10 - bar_filled)
        score_lines.append(f"  {component:<28} [{bar}] {s:>2}/{m}  {note}")

    console.print(Panel(
        f"[bold {color}]Quantum Risk Score: {score}/100  —  {label}[/bold {color}]\n\n"
        + "\n".join(score_lines) +
        f"\n\n[dim]Scoring model: Higher score = Higher quantum risk[/dim]\n"
        f"[dim]0–20: Fully Quantum Safe | 21–40: PQC Ready | 41–70: Medium Risk | 71–100: High Risk[/dim]",
        title="Quantum Risk Score (Weighted)", border_style=color
    ))

    # ── 4. CERTIFICATE DETAILS ─────────────────
    console.print(Panel(
        f"Issuer:              {scan['cert_issuer']}\n"
        f"Key Algorithm:       {scan['cert_key_algo']} {scan['cert_key_size']} bits\n"
        f"Signature Algorithm: {scan['cert_sig_algo']}\n"
        f"Expires:             {scan['cert_expiry']}",
        title="Certificate Details", border_style="cyan"
    ))

    # ── 5. RECOMMENDATIONS ────────────────────
    console.print(Panel(
        "\n".join(recs),
        title="Actionable Recommendations", border_style="yellow"
    ))


def display_summary_table(results):
    """Show CBOM summary of all scanned assets"""
    table = Table(
        title="CBOM Summary — All Assets",
        show_header=True, header_style="bold magenta",
        border_style="magenta"
    )
    table.add_column("Asset", style="cyan", width=32)
    table.add_column("IP", width=16)
    table.add_column("TLS", width=14)
    table.add_column("Key Exchange", width=18)
    table.add_column("Auth", width=12)
    table.add_column("Risk", width=6)
    table.add_column("FIPS 203", width=10)
    table.add_column("FIPS 204", width=10)
    table.add_column("FIPS 205", width=10)
    table.add_column("Status", width=22)

    for r in results:
        scan = r["scan"]
        score = r["score"]
        label = r["label"]
        fips = check_fips_compliance(scan)
        color = "green" if score <= 20 else "green" if score <= 40 else "yellow" if score <= 70 else "red"

        table.add_row(
            scan["host"],
            r.get("ip", "N/A"),
            ", ".join(scan["tls_versions"][-2:]) if scan["tls_versions"] else "N/A",
            scan["key_exchange"][:18],
            scan["cert_key_algo"][:12],
            f"[{color}]{score}[/{color}]",
            "[green]✅[/green]" if fips["FIPS 203"] else "[red]❌[/red]",
            "[green]✅[/green]" if fips["FIPS 204"] else "[red]❌[/red]",
            "[green]✅[/green]" if fips["FIPS 205"] else "[red]❌[/red]",
            f"[{color}]{label[:20]}[/{color}]"
        )

    console.print(table)


# ─────────────────────────────────────────────
# STEP 7: SAVE CBOM AS JSON
# ─────────────────────────────────────────────

def save_cbom(domain, results):
    cbom = {
        "scan_date": datetime.now().isoformat(),
        "target_domain": domain,
        "total_assets": len(results),
        "scoring_model": {
            "description": "Bank-focused quantum risk scoring (higher = more risk)",
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
        "fips_standards_checked": {
            "FIPS 203": "ML-KEM — Key Encapsulation",
            "FIPS 204": "ML-DSA — Digital Signatures",
            "FIPS 205": "SLH-DSA — Hash-based Signatures"
        },
        "assets": []
    }

    for r in results:
        scan = r["scan"]
        fips = check_fips_compliance(scan)
        cbom["assets"].append({
            "host": scan["host"],
            "ip": r.get("ip", "N/A"),
            "tls_versions": scan["tls_versions"],
            "cipher_suites": scan["cipher_suites"],
            "key_exchange": scan["key_exchange"],
            "authentication": scan["authentication"],
            "symmetric": scan["symmetric"],
            "hashing": scan["hashing"],
            "certificate": {
                "key_algorithm": scan["cert_key_algo"],
                "key_size": scan["cert_key_size"],
                "issuer": scan["cert_issuer"],
                "expiry": scan["cert_expiry"],
                "signature_algorithm": scan["cert_sig_algo"]
            },
            "pqc_algorithms_detected": scan["pqc_algorithms"],
            "vulnerabilities": scan["vulnerabilities"],
            "fips_compliance": {
                "FIPS_203_ML_KEM": fips["FIPS 203"],
                "FIPS_204_ML_DSA": fips["FIPS 204"],
                "FIPS_205_SLH_DSA": fips["FIPS 205"],
                "overall_compliant": all(fips.values())
            },
            "quantum_risk_score": r["score"],
            "risk_label": r["label"],
            "score_breakdown": {
                k: {"score": v["score"], "max": v["max"], "note": v["note"]}
                for k, v in r["breakdown"].items()
            },
            "recommendations": r["recs"],
            "migration_roadmap": r["roadmap"]
        })

    filename = f"CBOM_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(cbom, f, indent=2)

    console.print(f"\n[green]💾 CBOM saved to {filename}[/green]")
    return filename


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    console.print(Panel(
        "[bold cyan]QuantumShield — PQC Readiness Scanner[/bold cyan]\n"
        "[white]Cryptographic Bill of Materials Generator[/white]\n"
        "[dim]PNB Cybersecurity Hackathon 2025-26[/dim]",
        border_style="cyan"
    ))

    domain = input("\nEnter target domain (e.g. sbi.co.in): ").strip()
    if not domain:
        domain = "sbi.co.in"

    # Phase 1: Discovery
    subdomains = discover_subdomains(domain)

    # Phase 2: Filter live hosts
    live_hosts = filter_live_hosts(subdomains)

    if not live_hosts:
        console.print("[red]No live hosts found. Try a different domain.[/red]")
        sys.exit(1)

    # Phase 3-5: Scan each host
    all_results = []
    for host_info in live_hosts:
        host = host_info["host"]
        ip = host_info["ip"]

        scan = scan_tls(host)
        if not scan:
            continue

        score, breakdown = compute_qvs(scan)
        label = get_label(score)
        recs = get_recommendations(scan)
        roadmap = get_migration_roadmap(score)

        display_asset_result(scan, score, breakdown, label, recs)

        all_results.append({
            "scan": scan,
            "ip": ip,
            "score": score,
            "breakdown": breakdown,
            "label": label,
            "recs": recs,
            "roadmap": roadmap
        })

    # Phase 6: Summary
    if all_results:
        console.print("\n" + "="*80)
        display_summary_table(all_results)

        # Phase 7: Save CBOM
        save_cbom(domain, all_results)

        # PQC Certificate
        pqc_ready = [r for r in all_results if r["score"] <= 20]
        fips_full  = [r for r in all_results if all(check_fips_compliance(r["scan"]).values())]

        if fips_full:
            console.print(Panel(
                f"[bold gold1]🏆 PQC READY CERTIFICATE — NIST FIPS COMPLIANT[/bold gold1]\n\n"
                f"The following assets implement NIST-standardized\n"
                f"Post-Quantum Cryptography (FIPS 203 + FIPS 204 + FIPS 205):\n\n"
                + "\n".join([f"  ✅ {r['scan']['host']}" for r in fips_full]) +
                f"\n\n[dim]Issued: {datetime.now().strftime('%Y-%m-%d')}[/dim]\n"
                f"[dim]Standards: FIPS 203 (ML-KEM) | FIPS 204 (ML-DSA) | FIPS 205 (SLH-DSA)[/dim]",
                border_style="gold1"
            ))
        elif pqc_ready:
            console.print(Panel(
                f"[bold green]✅ FULLY QUANTUM SAFE (Risk Score ≤ 20)[/bold green]\n\n"
                + "\n".join([f"  ✅ {r['scan']['host']} — Score: {r['score']}/100" for r in pqc_ready]),
                title="Quantum Safe Status", border_style="green"
            ))
        else:
            worst = max(all_results, key=lambda r: r["score"])
            console.print(Panel(
                f"[red]No assets are currently PQC Ready or FIPS compliant.[/red]\n\n"
                f"Highest risk asset: {worst['scan']['host']} — Score: {worst['score']}/100\n"
                f"Status: {worst['label']}\n\n"
                f"Follow the migration roadmap to achieve FIPS 203/204/205 compliance.",
                title="PQC Certificate Status", border_style="red"
            ))

if __name__ == "__main__":
    main()
