"""
Module: Default Password Scanner
- Checks default credentials for CCTV camera brands
- Hikvision, Dahua, Axis, TP-Link, Reolink, Generic
- Supports rockyou.txt wordlist
- Fixed: proper response validation (no false positives)
"""

import requests
import time
import base64
import os
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from utils.banner import print_success, print_warning, print_error, print_info, print_critical

requests.packages.urllib3.disable_warnings()

# Default credentials database
DEFAULT_CREDS = {
    "hikvision": [
        ("admin", "12345"), ("admin", "admin"), ("admin", "Admin12345"),
        ("admin", "password"), ("admin", ""), ("888888", "888888"),
        ("admin", "hik12345"), ("admin", "hikadmin"), ("666666", "666666"),
    ],
    "dahua": [
        ("admin", "admin"), ("admin", ""), ("admin", "admin123"),
        ("admin", "dahua123"), ("admin", "12345"), ("888888", "888888"),
    ],
    "axis": [
        ("root", "pass"), ("root", "root"), ("admin", "admin"),
        ("root", ""), ("root", "admin"),
    ],
    "tplink": [
        ("admin", "admin"), ("admin", ""), ("admin", "tp-link"),
        ("admin", "12345"), ("admin", "123456"),
    ],
    "reolink": [
        ("admin", ""), ("admin", "admin"), ("admin", "12345678"),
    ],
    "generic": [
        ("admin", "admin"), ("admin", "1234"), ("admin", "12345"),
        ("admin", "123456"), ("admin", ""), ("admin", "password"),
        ("admin", "0000"), ("root", "root"), ("admin", "admin123"),
        ("admin", "888888"), ("guest", "guest"),
    ]
}

# Keywords that indicate successful login
LOGIN_SUCCESS_KEYWORDS = [
    "logout", "dashboard", "welcome", "sign out", "log out",
    "main.html", "index.html", "live view", "liveview",
    "channel", "camera", "preview", "monitor", "playback",
    "setup", "configuration", "settings", "system info",
    "statusvalue>200", '"statuscode":200', '"code":200',
    "isapi/security/usercheck",
]

# Keywords that indicate login failure
LOGIN_FAIL_KEYWORDS = [
    "invalid", "incorrect", "failed", "unauthorized",
    "wrong password", "login failed", "error", "denied",
    "bad credentials", "authentication failed",
]

# CCTV Web Interface paths
LOGIN_PATHS = [
    "/",
    "/login",
    "/admin",
    "/web/index.html",
    "/doc/index.html",
    "/ISAPI/Security/userCheck",
    "/cgi-bin/main-cgi",
    "/cgi-bin/mjpg/video.cgi",
    "/onvif/device_service",
    "/api/v1/login",
]


class DefaultPasswordScanner:
    def __init__(self, target_ip, port=80, brand="generic",
                 use_https=False, wordlist_path=None):
        self.target_ip     = target_ip
        self.port          = port
        self.brand         = brand.lower()
        self.use_https     = use_https
        self.protocol      = "https" if use_https else "http"
        self.base_url      = f"{self.protocol}://{target_ip}:{port}"
        self.findings      = []
        self.session       = requests.Session()
        self.session.verify = False
        self.timeout       = 8
        self.wordlist_path = wordlist_path  # path to rockyou.txt or custom wordlist

        # Baseline fingerprint (what the login page looks like unauthenticated)
        self._login_page_hash = None
        self._login_page_len  = None

    # ── Public entry point ────────────────────────────────────────
    def run_scan(self):
        print_info(f"Target: {self.base_url}")
        print_info(f"Brand:  {self.brand.upper()}")
        print_info("Starting Default Password Scan...\n")

        results = {
            "target":            self.base_url,
            "brand":             self.brand,
            "reachable":         False,
            "vulnerable":        False,
            "credentials_found": [],
            "findings":          []
        }

        # Step 1: Reachability
        if not self._is_reachable():
            print_error(f"Target {self.base_url} is not reachable")
            results["findings"].append({
                "status":      "ERROR",
                "title":       "Target Unreachable",
                "severity":    "INFO",
                "description": f"Could not connect to {self.base_url}"
            })
            return results

        results["reachable"] = True
        print_success(f"Target is reachable: {self.base_url}")

        # Step 2: Detect web interface & build baseline
        interface = self._detect_interface()
        if interface:
            print_success(f"Web interface found: {interface}")
        self._build_baseline()

        # Step 3: Default credentials
        print_info("Testing default credentials...")
        creds = DEFAULT_CREDS.get(self.brand, DEFAULT_CREDS["generic"])
        self._test_credentials(creds, results)

        # Step 4: rockyou.txt / custom wordlist (username = admin)
        if self.wordlist_path and os.path.exists(self.wordlist_path):
            print_info(f"\nLoading wordlist: {self.wordlist_path}")
            wordlist_creds = self._load_wordlist(self.wordlist_path)
            print_info(f"Testing {len(wordlist_creds)} passwords from wordlist...")
            self._test_credentials(wordlist_creds, results)
        elif self.wordlist_path:
            print_warning(f"Wordlist not found: {self.wordlist_path}")

        # Step 5: Summary
        if not results["credentials_found"]:
            print_success("No default credentials worked — Password likely changed")
            results["findings"].append({
                "status":      "PASS",
                "title":       "Default Credentials Not Working",
                "severity":    "LOW",
                "description": "All tested credentials failed. Password has been changed."
            })

        return results

    # ── Credential testing ────────────────────────────────────────
    def _test_credentials(self, creds, results):
        for username, password in creds:
            time.sleep(0.3)
            result = self._try_credential(username, password)
            if result["success"]:
                print_critical(f"DEFAULT CREDENTIALS WORK! {username}:{password} [{result['method']}]")
                results["vulnerable"] = True
                results["credentials_found"].append(f"{username}:{password}")
                results["findings"].append({
                    "status":      "FAIL",
                    "title":       f"Default Credentials: {username}:{password}",
                    "severity":    "CRITICAL",
                    "description": (
                        f"Camera accessible with default credentials via {result['method']}. "
                        "Attacker can view live feed, modify settings, disable camera."
                    )
                })
                self.findings.append(results["findings"][-1])
                # Stop after first confirmed hit to avoid flooding
                return
            else:
                display_pass = password if password else "(empty)"
                print_info(f"Tested: {username}:{display_pass} — Failed")

    # ── Credential attempt (with proper validation) ───────────────
    def _try_credential(self, username, password):

        # --- Method 1: Hikvision ISAPI ---
        try:
            login_url   = f"{self.base_url}/ISAPI/Security/userCheck"
            credentials = base64.b64encode(
                f"{username}:{password}".encode()
            ).decode()
            headers = {"Authorization": f"Basic {credentials}"}
            resp = self.session.get(login_url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                body = resp.text.lower()
                if ('"200"' in body or
                        "<statusvalue>200</statusvalue>" in body or
                        "statusvalue>200" in body):
                    return {"success": True, "method": "Hikvision ISAPI"}
        except Exception:
            pass

        # --- Method 2: HTTP Basic Auth ---
        try:
            resp = self.session.get(
                self.base_url,
                auth=HTTPBasicAuth(username, password),
                timeout=self.timeout
            )
            if self._is_successful_response(resp, "Basic Auth"):
                return {"success": True, "method": "Basic Auth"}
        except Exception:
            pass

        # --- Method 3: HTTP Digest Auth ---
        try:
            resp = self.session.get(
                self.base_url,
                auth=HTTPDigestAuth(username, password),
                timeout=self.timeout
            )
            if self._is_successful_response(resp, "Digest Auth"):
                return {"success": True, "method": "Digest Auth"}
        except Exception:
            pass

        return {"success": False}

    # ── Response validation (core fix) ───────────────────────────
    def _is_successful_response(self, resp, method):
        """
        True only if the response genuinely looks like a logged-in page.
        Prevents false positives where any 200 is treated as success.
        """
        if resp.status_code not in (200, 302):
            return False

        body = resp.text.lower()

        # Reject if response is identical to unauthenticated baseline
        if self._login_page_len is not None:
            if abs(len(resp.text) - self._login_page_len) < 50:
                return False

        # Reject if failure keywords present
        for kw in LOGIN_FAIL_KEYWORDS:
            if kw in body:
                return False

        # Accept only if success keywords present
        for kw in LOGIN_SUCCESS_KEYWORDS:
            if kw in body:
                return True

        # 401 → 200 transition without success keywords = likely still login page
        return False

    # ── Baseline builder ──────────────────────────────────────────
    def _build_baseline(self):
        """Capture unauthenticated login page to compare against."""
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            self._login_page_len  = len(resp.text)
        except Exception:
            pass

    # ── Reachability ──────────────────────────────────────────────
    def _is_reachable(self):
        try:
            self.session.get(self.base_url, timeout=self.timeout)
            return True
        except Exception:
            return False

    # ── Interface detection ───────────────────────────────────────
    def _detect_interface(self):
        for path in LOGIN_PATHS:
            try:
                resp = self.session.get(
                    f"{self.base_url}{path}", timeout=self.timeout
                )
                if resp.status_code in (200, 401, 403):
                    return f"{self.base_url}{path}"
            except Exception:
                continue
        return None

    # ── Wordlist loader ───────────────────────────────────────────
    def _load_wordlist(self, path, username="admin", max_passwords=10000):
        """
        Load passwords from rockyou.txt (or any newline-separated file).
        Pairs each password with the given username.
        Limits to max_passwords to avoid extremely long scans.
        """
        creds = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i >= max_passwords:
                        break
                    password = line.strip()
                    if password:
                        creds.append((username, password))
        except Exception as e:
            print_error(f"Error reading wordlist: {e}")
        return creds
        
