import requests
import sys

# Obeid Williams pySecure-Audit Tool
# Obeid Williams Developed as a lightweight security utility for HTTP header verification

class SecurityScanner:
    def __init__(self, target_url):
        self.url = target_url
        self.headers_to_check = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Referrer-Policy"
        ]

    def run_audit(self):
        print(f"--- Initiating Security Audit for: {self.url} ---\n")
        try:
            # Set a user-agent to avoid being blocked by simple bot filters
            headers = {'User-Agent': 'Security-Audit-Script-1.0'}
            response = requests.get(self.url, headers=headers, timeout=10)
            self.analyze_headers(response.headers)
        except requests.exceptions.RequestException as e:
            print(f"[!] Error: Could not connect to target. {e}")

    def analyze_headers(self, headers):
        findings = 0
        for header in self.headers_to_check:
            if header in headers:
                print(f"[+] PASSED: {header} is present.")
            else:
                print(f"[-] MISSING: {header} (Security Risk Identified)")
                findings += 1
        
        print(f"\n--- Audit Complete: {findings} security gaps identified. ---")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <url>")
    else:
        target = sys.argv[1]
        # Auto-format URL if protocol is missing
        if not target.startswith("http"):
            target = "https://" + target
        
        scanner = SecurityScanner(target)
        scanner.run_audit()
