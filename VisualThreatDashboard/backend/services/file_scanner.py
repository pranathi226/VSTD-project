"""
File Scanner — Analyzes uploaded files for hacking tools, malware indicators,
suspicious patterns, and known threat signatures.
"""

import os
import re
import hashlib
import magic  # python-magic for MIME type detection
from datetime import datetime
from typing import Dict, Any, List


# ─────────────────────────────────────────────────
# Known hacking tool signatures & malicious patterns
# ─────────────────────────────────────────────────

HACKING_TOOL_SIGNATURES = {
    # Reverse shells
    r"socket\.connect\s*\(": {"name": "Reverse Shell (Python)", "severity": "Critical", "category": "Reverse Shell"},
    r"bash\s+-i\s+>&\s*/dev/tcp": {"name": "Bash Reverse Shell", "severity": "Critical", "category": "Reverse Shell"},
    r"nc\s+-[elp].*\d+": {"name": "Netcat Listener/Shell", "severity": "Critical", "category": "Reverse Shell"},
    r"ncat.*--exec": {"name": "Ncat Shell Execution", "severity": "Critical", "category": "Reverse Shell"},
    r"powershell.*-e\s+[A-Za-z0-9+/=]+": {"name": "PowerShell Encoded Command", "severity": "Critical", "category": "Obfuscation"},
    r"python\s+-c.*import\s+socket": {"name": "Python Socket One-liner", "severity": "High", "category": "Reverse Shell"},
    r"perl\s+-e.*socket": {"name": "Perl Reverse Shell", "severity": "Critical", "category": "Reverse Shell"},
    r"ruby\s+-rsocket": {"name": "Ruby Reverse Shell", "severity": "Critical", "category": "Reverse Shell"},
    r"php\s+-r.*fsockopen": {"name": "PHP Reverse Shell", "severity": "Critical", "category": "Reverse Shell"},

    # Exploitation frameworks
    r"msfvenom|msfconsole|metasploit": {"name": "Metasploit Framework", "severity": "Critical", "category": "Exploit Framework"},
    r"from\s+impacket": {"name": "Impacket Library", "severity": "High", "category": "Exploit Framework"},
    r"import\s+scapy": {"name": "Scapy Packet Manipulation", "severity": "Medium", "category": "Network Tool"},
    r"from\s+pwntools|from\s+pwn\s+import": {"name": "Pwntools Exploit Framework", "severity": "Critical", "category": "Exploit Framework"},
    r"import\s+paramiko.*exec_command": {"name": "SSH Brute Force Tool", "severity": "High", "category": "Brute Force"},

    # Credential harvesting
    r"mimikatz|sekurlsa|kerberos::": {"name": "Mimikatz Credential Dumper", "severity": "Critical", "category": "Credential Theft"},
    r"hashcat|john\s+the\s+ripper|john\s+--": {"name": "Password Cracker", "severity": "High", "category": "Password Cracking"},
    r"hydra\s+-[lLpP]": {"name": "Hydra Brute Forcer", "severity": "Critical", "category": "Brute Force"},
    r"aircrack-ng|airmon-ng|aireplay": {"name": "WiFi Cracking Tool", "severity": "Critical", "category": "WiFi Attack"},

    # Keyloggers & spyware
    r"pynput.*keyboard|keyboard\.on_press": {"name": "Keylogger (Python)", "severity": "Critical", "category": "Keylogger"},
    r"GetAsyncKeyState|SetWindowsHookEx": {"name": "Windows Keylogger API", "severity": "Critical", "category": "Keylogger"},
    r"screenshot|pyautogui\.screenshot|ImageGrab": {"name": "Screen Capture Tool", "severity": "High", "category": "Spyware"},
    r"webcam|VideoCapture\(0\)": {"name": "Webcam Access", "severity": "High", "category": "Spyware"},
    r"win32clipboard|pyperclip": {"name": "Clipboard Monitor", "severity": "Medium", "category": "Spyware"},

    # Privilege escalation
    r"sudo\s+-l|NOPASSWD": {"name": "Sudo Privilege Check", "severity": "Medium", "category": "Privilege Escalation"},
    r"chmod\s+[47]777|chmod\s+u\+s": {"name": "SUID/Permission Escalation", "severity": "High", "category": "Privilege Escalation"},
    r"LinEnum|linpeas|winpeas": {"name": "Privilege Escalation Script", "severity": "Critical", "category": "Privilege Escalation"},

    # Network scanning & recon
    r"nmap\s+-[sS]": {"name": "Nmap Port Scanner", "severity": "Medium", "category": "Reconnaissance"},
    r"masscan\s+": {"name": "Masscan Port Scanner", "severity": "Medium", "category": "Reconnaissance"},
    r"gobuster|dirb|dirbuster|ffuf": {"name": "Directory Brute Forcer", "severity": "Medium", "category": "Reconnaissance"},
    r"sqlmap": {"name": "SQLMap SQL Injection Tool", "severity": "Critical", "category": "SQL Injection"},
    r"nikto\s+-h": {"name": "Nikto Web Scanner", "severity": "Medium", "category": "Reconnaissance"},

    # Malware patterns
    r"exec\(base64_decode": {"name": "PHP Backdoor (Base64)", "severity": "Critical", "category": "Backdoor"},
    r"eval\(atob\(|eval\(Buffer\.from": {"name": "JS Obfuscated Payload", "severity": "Critical", "category": "Obfuscation"},
    r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}": {"name": "Shellcode Pattern", "severity": "Critical", "category": "Shellcode"},
    r"CreateRemoteThread|VirtualAllocEx|WriteProcessMemory": {"name": "Process Injection (Windows)", "severity": "Critical", "category": "Malware"},
    r"os\.system\(|subprocess\.call\(|subprocess\.Popen\(": {"name": "System Command Execution", "severity": "Medium", "category": "Command Execution"},
    r"ctypes\.windll|kernel32|ntdll": {"name": "Windows API Access", "severity": "High", "category": "System Access"},

    # Data exfiltration
    r"smtp.*send_message|smtplib": {"name": "Email Exfiltration", "severity": "High", "category": "Data Exfiltration"},
    r"ftplib.*stor|paramiko.*put": {"name": "File Exfiltration (FTP/SSH)", "severity": "High", "category": "Data Exfiltration"},
    r"requests\.post.*upload|urllib.*upload": {"name": "HTTP Data Upload", "severity": "Medium", "category": "Data Exfiltration"},
    r"telegram.*bot.*send|discord.*webhook": {"name": "Bot C2 Communication", "severity": "Critical", "category": "Command & Control"},

    # Ransomware indicators
    r"Fernet\(.*encrypt|AES\.new.*encrypt": {"name": "File Encryption (Ransomware Pattern)", "severity": "Critical", "category": "Ransomware"},
    r"\.encrypted|\.locked|\.ransom": {"name": "Ransomware File Extension", "severity": "High", "category": "Ransomware"},
    r"bitcoin|btc.*wallet|monero|xmr": {"name": "Cryptocurrency Reference", "severity": "Medium", "category": "Ransomware"},

    # Web attacks
    r"<script>.*document\.cookie": {"name": "XSS Cookie Theft", "severity": "High", "category": "Web Attack"},
    r"UNION\s+SELECT|OR\s+1\s*=\s*1|DROP\s+TABLE": {"name": "SQL Injection Payload", "severity": "Critical", "category": "SQL Injection"},
    r"\.\./\.\./\.\./etc/passwd": {"name": "Path Traversal Attack", "severity": "Critical", "category": "Web Attack"},
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".pif",
    ".msi", ".dll", ".sys", ".com", ".hta", ".wsf", ".jar",
}

SUSPICIOUS_EXTENSIONS = {
    ".py", ".sh", ".rb", ".pl", ".php", ".jsp",
}


# ─────────────────────────────────────────────────
# File Scanner
# ─────────────────────────────────────────────────

def scan_file(filepath: str, filename: str) -> Dict[str, Any]:
    """
    Scan a file for hacking tools, malware indicators, and suspicious patterns.
    Returns a detailed report.
    """
    result = {
        "filename": filename,
        "file_size": 0,
        "file_type": "unknown",
        "md5": "",
        "sha256": "",
        "scan_time": datetime.utcnow().isoformat(),
        "threats_found": [],
        "threat_count": 0,
        "risk_level": "Safe",
        "threat_score": 0,
        "is_dangerous_extension": False,
        "summary": "",
    }

    try:
        # File metadata
        file_size = os.path.getsize(filepath)
        result["file_size"] = file_size
        result["file_size_display"] = _format_size(file_size)

        # File hashes
        with open(filepath, "rb") as f:
            data = f.read()
        result["md5"] = hashlib.md5(data).hexdigest()
        result["sha256"] = hashlib.sha256(data).hexdigest()

        # MIME type detection
        try:
            mime = magic.Magic(mime=True)
            result["file_type"] = mime.from_file(filepath)
        except Exception:
            # Fallback to extension-based detection
            ext = os.path.splitext(filename)[1].lower()
            mime_map = {
                ".py": "text/x-python", ".js": "application/javascript",
                ".sh": "text/x-shellscript", ".bat": "text/x-batch",
                ".exe": "application/x-executable", ".txt": "text/plain",
                ".html": "text/html", ".php": "text/x-php",
                ".rb": "text/x-ruby", ".pl": "text/x-perl",
                ".ps1": "text/x-powershell", ".c": "text/x-c",
                ".cpp": "text/x-c++", ".java": "text/x-java",
            }
            result["file_type"] = mime_map.get(ext, "application/octet-stream")

        # Check dangerous extensions
        ext = os.path.splitext(filename)[1].lower()
        if ext in DANGEROUS_EXTENSIONS:
            result["is_dangerous_extension"] = True
            result["threats_found"].append({
                "name": f"Dangerous File Type ({ext})",
                "severity": "High",
                "category": "Suspicious File",
                "line": 0,
                "detail": f"File extension '{ext}' is commonly used by malware",
            })

        # Read file content for pattern matching (text files only)
        try:
            content = data.decode("utf-8", errors="ignore")
            lines = content.split("\n")

            # Scan each line against threat signatures
            for line_num, line in enumerate(lines, 1):
                for pattern, info in HACKING_TOOL_SIGNATURES.items():
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            # Avoid duplicate detections for same tool
                            already_found = any(
                                t["name"] == info["name"] for t in result["threats_found"]
                            )
                            if not already_found:
                                result["threats_found"].append({
                                    "name": info["name"],
                                    "severity": info["severity"],
                                    "category": info["category"],
                                    "line": line_num,
                                    "detail": line.strip()[:120],
                                })
                    except re.error:
                        pass

        except Exception:
            # Binary file — can't scan content
            pass

        # Calculate threat score
        score = 0
        for threat in result["threats_found"]:
            if threat["severity"] == "Critical":
                score += 25
            elif threat["severity"] == "High":
                score += 15
            elif threat["severity"] == "Medium":
                score += 8
            else:
                score += 3

        result["threat_score"] = min(score, 100)
        result["threat_count"] = len(result["threats_found"])

        # Assign risk level
        if result["threat_score"] == 0:
            result["risk_level"] = "Safe"
            result["summary"] = "No threats detected. File appears clean."
        elif result["threat_score"] <= 25:
            result["risk_level"] = "Low"
            result["summary"] = f"Minor concerns found ({result['threat_count']} indicator{'s' if result['threat_count'] > 1 else ''})."
        elif result["threat_score"] <= 60:
            result["risk_level"] = "Medium"
            result["summary"] = f"Suspicious patterns detected ({result['threat_count']} indicator{'s' if result['threat_count'] > 1 else ''}). Review recommended."
        else:
            result["risk_level"] = "High"
            result["summary"] = f"⚠ DANGER: Hacking tools or malware detected ({result['threat_count']} threat{'s' if result['threat_count'] > 1 else ''})!"

    except Exception as e:
        result["summary"] = f"Error scanning file: {str(e)}"
        result["risk_level"] = "Error"

    return result


def _format_size(size_bytes: int) -> str:
    """Format file size to human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"
