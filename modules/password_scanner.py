"""
Module 1: Default Password Scanner
- CCTV camera brands-ന്റെ default credentials check ചെയ്യുന്നു
- Hikvision, Dahua, Axis, TP-Link, Reolink, Generic
"""

import requests
import time
import base64
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
    def __init__(self, target_ip, port=80, brand="generic", use_https=False):
        self.target_ip = target_ip
        self.port = port
        self.brand = brand.lower()
        self.use_https = use_https
        self.protocol = "https" if use_https else "http"
        self.base_url = f"{self.protocol}://{target_ip}:{port}"
        self.findings = []
        self.session = requests.Session()
        self.session.verify = False
        self.timeout = 8

    def run_scan(self):
        print_info(f"Target: {self.base_url}")
        print_info(f"Brand: {self.brand.upper()}")
        print_info("Starting Default Password Scan...\n")

        results = {
            "target": self.base_url,
            "brand": self.brand,
            "reachable": False,
            "vulnerable": False,
            "credentials_found": [],
            "findings": []
        }

        # Step 1: Check if target is reachable
        if not self._is_reachable():
            print_error(f"Target {self.base_url} is not reachable")
            results["findings"].append({
                "status": "ERROR",
                "title": "Target Unreachable",
                "severity": "INFO",
                "description": f"Could not connect to {self.base_url}"
            })
            return results

        results["reachable"] = True
        print_success(f"Target is reachable: {self.base_url}")

        # Step 2: Detect web interface
        interface = self._detect_interface()
        if interface:
            print_success(f"Web interface found: {interface}")

        # Step 3: Try default credentials
        print_info("Testing default credentials...")
        creds_to_test = DEFAULT_CREDS.get(self.brand, DEFAULT_CREDS["generic"])

        for username, password in creds_to_test:
            time.sleep(0.3)
            result = self._try_credential(username, password)
            if result["success"]:
                print_critical(f"DEFAULT CREDENTIALS WORK! {username}:{password}")
                results["vulnerable"] = True
                results["credentials_found"].append(f"{username}:{password}")
                results["findings"].append({
                    "status": "FAIL",
                    "title": f"Default Credentials: {username}:{password}",
                    "severity": "CRITICAL",
                    "description": f"Camera accessible with default credentials. Attacker can view live feed, modify settings, disable camera."
                })
                self.findings.append(results["findings"][-1])
            else:
                print_info(f"Tested: {username}:{password if password else '(empty)'} — Failed")

        if not results["credentials_found"]:
            print_success("No default credentials worked — Password likely changed")
            results["findings"].append({
                "status": "PASS",
                "title": "Default Credentials Not Working",
                "severity": "LOW",
                "description": "Default credentials tested — none worked. Password has been changed."
            })

        return results

    def _is_reachable(self):
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            return True
        except:
            return False

    def _detect_interface(self):
        for path in LOGIN_PATHS:
            try:
                resp = self.session.get(f"{self.base_url}{path}", timeout=self.timeout)
                if resp.status_code in [200, 401, 403]:
                    return f"{self.base_url}{path}"
            except:
                continue
        return None

    def _try_credential(self, username, password):
        # Try HTTP Basic Auth
        try:
            resp = self.session.get(
                self.base_url,
                auth=HTTPBasicAuth(username, password),
                timeout=self.timeout
            )
            if resp.status_code == 200 and "login" not in resp.url.lower():
                return {"success": True, "method": "Basic Auth"}
        except:
            pass

        # Try HTTP Digest Auth
        try:
            resp = self.session.get(
                self.base_url,
                auth=HTTPDigestAuth(username, password),
                timeout=self.timeout
            )
            if resp.status_code == 200:
                return {"success": True, "method": "Digest Auth"}
        except:
            pass

        # Try form-based login (Hikvision style)
        try:
            login_url = f"{self.base_url}/ISAPI/Security/userCheck"
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers = {"Authorization": f"Basic {credentials}"}
            resp = self.session.get(login_url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200 and "statusValue" in resp.text:
                if '"200"' in resp.text or "<statusValue>200</statusValue>" in resp.text:
                    return {"success": True, "method": "Hikvision ISAPI"}
        except:
            pass

        return {"success": False}
