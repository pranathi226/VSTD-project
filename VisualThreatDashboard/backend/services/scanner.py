"""
Scanning services — Nmap, OWASP ZAP, VirusTotal, Custom Analyzer.

Each scanner returns a dict with:
  - raw_output: str
  - parsed_result: dict
  - threat_score: float (0-100)
  - risk_level: str ("Low" | "Medium" | "High")
"""

import re
import os
import json
import shlex
import socket
import ssl
import subprocess
from datetime import datetime
from typing import Dict, Any

import httpx


# ─────────────────────────────────────────────────
# Input validation — prevent command injection
# ─────────────────────────────────────────────────

_VALID_TARGET = re.compile(
    r"^(?:"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"  # domain
    r"|"
    r"(?:\d{1,3}\.){3}\d{1,3}"  # IPv4
    r")$"
)


def sanitize_target(target: str) -> str:
    """Validate and sanitize a scan target (IP or domain)."""
    target = target.strip().lower()
    if not _VALID_TARGET.match(target):
        raise ValueError(f"Invalid target: '{target}'. Must be an IP address or domain name.")
    return target


# ─────────────────────────────────────────────────
# Threat score & risk level helpers
# ─────────────────────────────────────────────────

def calculate_threat_score(parsed: Dict[str, Any]) -> float:
    """Calculate a threat score (0-100) from parsed scan results."""
    score = 0.0

    # Open ports contribute to score
    open_ports = parsed.get("open_ports", [])
    risky_ports = {21, 23, 25, 445, 3389, 8080, 8443}
    for port_info in open_ports:
        port = port_info.get("port", 0) if isinstance(port_info, dict) else port_info
        score += 5
        if port in risky_ports:
            score += 10

    # Vulnerabilities
    vulns = parsed.get("vulnerabilities", [])
    for v in vulns:
        risk = v.get("risk", "").lower() if isinstance(v, dict) else "medium"
        if risk == "high":
            score += 20
        elif risk == "medium":
            score += 10
        else:
            score += 5

    # VirusTotal detections
    detections = parsed.get("detections", 0)
    score += detections * 5

    # SSL issues
    if parsed.get("ssl_issues"):
        score += 15

    # DNS issues
    if parsed.get("dns_issues"):
        score += 10

    return min(score, 100.0)


def assign_risk_level(score: float) -> str:
    """Map threat score to risk level."""
    if score <= 33:
        return "Low"
    elif score <= 66:
        return "Medium"
    else:
        return "High"


# ─────────────────────────────────────────────────
# Nmap Scanner
# ─────────────────────────────────────────────────

def run_nmap(target: str) -> Dict[str, Any]:
    """Run nmap port scan and parse output."""
    target = sanitize_target(target)

    try:
        cmd = ["nmap", "-sV", "-T4", "--open", "-oG", "-", shlex.quote(target)]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        raw = result.stdout + result.stderr

        # Parse greppable output
        open_ports = []
        for line in raw.splitlines():
            if "/open/" in line:
                # Extract port info from greppable format
                port_section = line.split("Ports: ")[-1] if "Ports: " in line else ""
                for entry in port_section.split(","):
                    entry = entry.strip()
                    parts = entry.split("/")
                    if len(parts) >= 5:
                        open_ports.append({
                            "port": int(parts[0]) if parts[0].isdigit() else 0,
                            "state": parts[1],
                            "protocol": parts[2],
                            "service": parts[4],
                        })

        parsed = {"open_ports": open_ports, "host": target}
        score = calculate_threat_score(parsed)

        return {
            "raw_output": raw[:5000],
            "parsed_result": parsed,
            "threat_score": score,
            "risk_level": assign_risk_level(score),
        }

    except FileNotFoundError:
        return {
            "raw_output": "Error: nmap is not installed. Install it via 'sudo apt install nmap' or from https://nmap.org",
            "parsed_result": {"error": "nmap_not_installed"},
            "threat_score": 0,
            "risk_level": "Low",
        }
    except subprocess.TimeoutExpired:
        return {
            "raw_output": "Error: nmap scan timed out after 120 seconds",
            "parsed_result": {"error": "timeout"},
            "threat_score": 0,
            "risk_level": "Low",
        }
    except Exception as e:
        return {
            "raw_output": f"Error running nmap: {str(e)}",
            "parsed_result": {"error": str(e)},
            "threat_score": 0,
            "risk_level": "Low",
        }


# ─────────────────────────────────────────────────
# OWASP ZAP Scanner
# ─────────────────────────────────────────────────

def run_zap(target: str) -> Dict[str, Any]:
    """Run OWASP ZAP quick scan (CLI mode)."""
    target = sanitize_target(target)
    url = f"http://{target}" if not target.startswith("http") else target

    try:
        cmd = ["zap-cli", "quick-scan", "--self-contained", "-l", "Informational", url]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        raw = result.stdout + result.stderr

        # Parse ZAP output for alerts
        vulnerabilities = []
        for line in raw.splitlines():
            line_lower = line.lower()
            if any(kw in line_lower for kw in ["alert", "risk", "high", "medium", "low"]):
                risk = "high" if "high" in line_lower else ("medium" if "medium" in line_lower else "low")
                vulnerabilities.append({
                    "description": line.strip(),
                    "risk": risk,
                })

        parsed = {"vulnerabilities": vulnerabilities, "target_url": url}
        score = calculate_threat_score(parsed)

        return {
            "raw_output": raw[:5000],
            "parsed_result": parsed,
            "threat_score": score,
            "risk_level": assign_risk_level(score),
        }

    except FileNotFoundError:
        return {
            "raw_output": "Error: zap-cli is not installed. Install OWASP ZAP and zap-cli.",
            "parsed_result": {"error": "zap_not_installed"},
            "threat_score": 0,
            "risk_level": "Low",
        }
    except subprocess.TimeoutExpired:
        return {
            "raw_output": "Error: ZAP scan timed out after 300 seconds",
            "parsed_result": {"error": "timeout"},
            "threat_score": 0,
            "risk_level": "Low",
        }
    except Exception as e:
        return {
            "raw_output": f"Error running ZAP: {str(e)}",
            "parsed_result": {"error": str(e)},
            "threat_score": 0,
            "risk_level": "Low",
        }


# ─────────────────────────────────────────────────
# VirusTotal API
# ─────────────────────────────────────────────────

async def run_virustotal(target: str) -> Dict[str, Any]:
    """Query VirusTotal API v3 for domain/IP analysis."""
    target = sanitize_target(target)
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")

    if not api_key or api_key.startswith("your-"):
        return {
            "raw_output": "VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY in .env",
            "parsed_result": {"error": "no_api_key"},
            "threat_score": 0,
            "risk_level": "Low",
        }

    # Determine if target is IP or domain
    is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target)
    endpoint = f"ip_addresses/{target}" if is_ip else f"domains/{target}"

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/{endpoint}",
                headers={"x-apikey": api_key},
            )

        if resp.status_code != 200:
            return {
                "raw_output": f"VirusTotal API error: {resp.status_code} — {resp.text[:500]}",
                "parsed_result": {"error": f"api_error_{resp.status_code}"},
                "threat_score": 0,
                "risk_level": "Low",
            }

        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})

        # Last analysis stats
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 1

        parsed = {
            "detections": malicious + suspicious,
            "total_engines": total,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "last_analysis_date": attrs.get("last_analysis_date"),
        }

        score = calculate_threat_score(parsed)

        return {
            "raw_output": json.dumps(parsed, indent=2),
            "parsed_result": parsed,
            "threat_score": score,
            "risk_level": assign_risk_level(score),
        }

    except Exception as e:
        return {
            "raw_output": f"Error querying VirusTotal: {str(e)}",
            "parsed_result": {"error": str(e)},
            "threat_score": 0,
            "risk_level": "Low",
        }


# ─────────────────────────────────────────────────
# Custom Python Threat Analyzer
# ─────────────────────────────────────────────────

def run_custom_analyzer(target: str) -> Dict[str, Any]:
    """Custom Python-based threat analyzer — DNS, port probing, SSL check."""
    target = sanitize_target(target)
    results = {
        "dns": {},
        "open_ports": [],
        "ssl_issues": False,
        "dns_issues": False,
    }
    raw_lines = [f"=== Custom Threat Analysis for {target} ===\n"]

    # ── 1. DNS Resolution ──
    try:
        ips = socket.getaddrinfo(target, None)
        resolved = list({addr[4][0] for addr in ips})
        results["dns"] = {"resolved_ips": resolved}
        raw_lines.append(f"[DNS] Resolved to: {', '.join(resolved)}")
    except socket.gaierror:
        results["dns"] = {"error": "DNS resolution failed"}
        results["dns_issues"] = True
        raw_lines.append(f"[DNS] ⚠ Resolution FAILED for {target}")

    # ── 2. Common Port Probing ──
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
    for port in common_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                if s.connect_ex((target, port)) == 0:
                    results["open_ports"].append({"port": port, "state": "open"})
                    raw_lines.append(f"[PORT] {port}/tcp — OPEN")
        except Exception:
            pass

    # ── 3. SSL Certificate Check (port 443) ──
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(3)
            s.connect((target, 443))
            cert = s.getpeercert()
            not_after = cert.get("notAfter", "")
            raw_lines.append(f"[SSL] Certificate valid until: {not_after}")

            # Check expiry
            from datetime import datetime as dt
            try:
                expiry = dt.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                if expiry < dt.utcnow():
                    results["ssl_issues"] = True
                    raw_lines.append("[SSL] ⚠ Certificate EXPIRED!")
            except Exception:
                pass
    except Exception as e:
        raw_lines.append(f"[SSL] No SSL/TLS on port 443 or error: {str(e)[:80]}")

    raw_output = "\n".join(raw_lines)
    score = calculate_threat_score(results)

    return {
        "raw_output": raw_output,
        "parsed_result": results,
        "threat_score": score,
        "risk_level": assign_risk_level(score),
    }


# ─────────────────────────────────────────────────
# Dispatcher
# ─────────────────────────────────────────────────

async def dispatch_scan(tool: str, target: str) -> Dict[str, Any]:
    """Route to the correct scanner based on tool name."""
    if tool == "nmap":
        return run_nmap(target)
    elif tool == "zap":
        return run_zap(target)
    elif tool == "virustotal":
        return await run_virustotal(target)
    elif tool == "custom":
        return run_custom_analyzer(target)
    else:
        return {
            "raw_output": f"Unknown tool: {tool}",
            "parsed_result": {"error": "unknown_tool"},
            "threat_score": 0,
            "risk_level": "Low",
        }
