"""
Module 3: Vulnerability Checker
- Known CVEs check ചെയ്യുന്നു
- Firmware version detect ചെയ്യുന്നു
- Unencrypted stream detection
- Authentication bypass attempts
"""

import requests
import time
from utils.banner import print_success, print_warning, print_error, print_info, print_critical

requests.packages.urllib3.disable_warnings()

# Known CCTV CVEs
KNOWN_CVES = {
    "CVE-2021-36260": {
        "brand": "hikvision",
        "name": "Hikvision Remote Code Execution",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "description": "Unauthenticated RCE via /SDK/webLanguage endpoint. Attacker can execute arbitrary commands.",
        "test_path": "/SDK/webLanguage",
        "test_method": "PUT",
        "indicator": "webLanguage"
    },
    "CVE-2017-7921": {
        "brand": "hikvision",
        "name": "Hikvision Authentication Bypass",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "description": "Authentication bypass allows access to snapshot and configuration without credentials.",
        "test_path": "/onvif-http/snapshot?auth=YWRtaW46MTEM",
        "test_method": "GET",
        "indicator": "snapshot"
    },
    "CVE-2019-9082": {
        "brand": "dahua",
        "name": "Dahua Authentication Bypass",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "description": "Remote code execution via crafted login request. Full camera takeover possible.",
        "test_path": "/RPC2_Login",
        "test_method": "POST",
        "indicator": "RPC2"
    },
    "CVE-2018-9995": {
        "brand": "generic",
        "name": "Generic DVR Authentication Bypass",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "description": "DVR devices accept crafted cookie to bypass authentication. Affects 100+ brands.",
        "test_path": "/device.rsp?opt=user&cmd=list",
        "test_method": "GET",
        "indicator": "user"
    },
    "CVE-2020-25078": {
        "brand": "dlink",
        "name": "D-Link Camera Credential Disclosure",
        "severity": "HIGH",
        "cvss": "7.5",
        "description": "Unauthenticated access to admin credentials via /config/getuser endpoint.",
        "test_path": "/config/getuser?index=0",
        "test_method": "GET",
        "indicator": "username"
    },
    "CVE-2021-33044": {
        "brand": "dahua",
        "name": "Dahua Identity Authentication Bypass",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "description": "Authentication bypass during device initialization allows admin access.",
        "test_path": "/RPC2",
        "test_method": "POST",
        "indicator": "RPC"
    },
}


class VulnerabilityChecker:
    def __init__(self, target_ip, port=80, brand="generic", use_https=False):
        self.target_ip = target_ip
        self.port = port
        self.brand = brand.lower()
        self.use_https = use_https
        self.protocol = "https" if use_https else "http"
        self.base_url = f"{self.protocol}://{target_ip}:{port}"
        self.session = requests.Session()
        self.session.verify = False
        self.timeout = 8
        self.findings = []

    def run_checks(self, demo=False):
        print_info(f"Target: {self.base_url}")
        print_info("Running Vulnerability Assessment...\n")

        if demo:
            return self._demo_checks()

        results = []

        # Check 1: CVE scanning
        print_info("Checking known CVEs...")
        cve_results = self._check_cves()
        results.extend(cve_results)

        # Check 2: Unencrypted stream
        print_info("Checking for unencrypted RTSP stream...")
        stream_result = self._check_unencrypted_stream()
        results.append(stream_result)

        # Check 3: Telnet open
        print_info("Checking for open Telnet...")
        telnet_result = self._check_telnet()
        results.append(telnet_result)

        # Check 4: ONVIF without auth
        print_info("Checking ONVIF authentication...")
        onvif_result = self._check_onvif()
        results.append(onvif_result)

        # Check 5: Firmware version disclosure
        print_info("Checking firmware version disclosure...")
        fw_result = self._check_firmware_disclosure()
        results.append(fw_result)

        # Check 6: Directory listing
        print_info("Checking for directory listing...")
        dir_result = self._check_directory_listing()
        results.append(dir_result)

        return results

    def _check_cves(self):
        results = []
        for cve_id, cve_info in KNOWN_CVES.items():
            if cve_info["brand"] in [self.brand, "generic"]:
                try:
                    url = f"{self.base_url}{cve_info['test_path']}"
                    if cve_info["test_method"] == "GET":
                        resp = self.session.get(url, timeout=self.timeout)
                    else:
                        resp = self.session.post(url, timeout=self.timeout)

                    if resp.status_code in [200, 401] and cve_info["indicator"].lower() in resp.text.lower():
                        print_critical(f"{cve_id}: {cve_info['name']} — POTENTIALLY VULNERABLE!")
                        results.append({
                            "status": "FAIL",
                            "title": f"{cve_id}: {cve_info['name']}",
                            "severity": cve_info["severity"],
                            "cvss": cve_info["cvss"],
                            "description": cve_info["description"]
                        })
                    else:
                        print_success(f"{cve_id} — Not vulnerable")
                        results.append({
                            "status": "PASS",
                            "title": f"{cve_id}: {cve_info['name']}",
                            "severity": "LOW",
                            "description": "Not vulnerable to this CVE"
                        })
                except Exception as e:
                    print_info(f"{cve_id} — Could not test: {str(e)[:30]}")
                time.sleep(0.3)
        return results

    def _check_unencrypted_stream(self):
        try:
            import socket
            s = socket.socket()
            s.settimeout(3)
            result = s.connect_ex((self.target_ip, 554))
            s.close()
            if result == 0:
                print_warning("RTSP port 554 open — Stream may be unencrypted!")
                return {
                    "status": "FAIL",
                    "title": "Unencrypted RTSP Stream",
                    "severity": "HIGH",
                    "description": f"RTSP port 554 is open. Stream URL: rtsp://{self.target_ip}/stream. Anyone on the network can view the camera feed."
                }
            else:
                print_success("RTSP port 554 closed")
                return {"status": "PASS", "title": "RTSP Stream", "severity": "LOW", "description": "RTSP not exposed"}
        except:
            return {"status": "INFO", "title": "RTSP Check", "severity": "LOW", "description": "Could not check RTSP"}

    def _check_telnet(self):
        try:
            import socket
            s = socket.socket()
            s.settimeout(2)
            result = s.connect_ex((self.target_ip, 23))
            s.close()
            if result == 0:
                print_critical("Telnet port 23 OPEN — Critical security risk!")
                return {
                    "status": "FAIL",
                    "title": "Telnet Service Exposed",
                    "severity": "CRITICAL",
                    "description": "Telnet on port 23 is open. Unencrypted remote access possible. Disable immediately."
                }
            print_success("Telnet port closed")
            return {"status": "PASS", "title": "Telnet Check", "severity": "LOW", "description": "Telnet not exposed"}
        except:
            return {"status": "INFO", "title": "Telnet Check", "severity": "LOW", "description": "Could not check Telnet"}

    def _check_onvif(self):
        try:
            onvif_url = f"{self.base_url}/onvif/device_service"
            resp = self.session.get(onvif_url, timeout=self.timeout)
            if resp.status_code == 200 and "onvif" in resp.text.lower():
                print_warning("ONVIF endpoint accessible without authentication!")
                return {
                    "status": "FAIL",
                    "title": "ONVIF Unauthenticated Access",
                    "severity": "HIGH",
                    "description": "ONVIF device service accessible without credentials. Camera metadata and stream URLs exposed."
                }
            print_success("ONVIF requires authentication")
            return {"status": "PASS", "title": "ONVIF Authentication", "severity": "LOW", "description": "ONVIF properly protected"}
        except:
            return {"status": "INFO", "title": "ONVIF Check", "severity": "LOW", "description": "ONVIF not detected"}

    def _check_firmware_disclosure(self):
        paths = ["/System/deviceInfo", "/cgi-bin/get_status.cgi", "/api/v1/info"]
        for path in paths:
            try:
                resp = self.session.get(f"{self.base_url}{path}", timeout=self.timeout)
                if resp.status_code == 200 and any(k in resp.text.lower() for k in ["firmware", "version", "model"]):
                    print_warning(f"Firmware version disclosed at {path}")
                    return {
                        "status": "FAIL",
                        "title": "Firmware Version Disclosure",
                        "severity": "MEDIUM",
                        "description": f"Device info accessible without auth at {path}. Attackers can identify vulnerable firmware versions."
                    }
            except:
                pass
        print_success("No firmware version disclosure")
        return {"status": "PASS", "title": "Firmware Disclosure", "severity": "LOW", "description": "No firmware info disclosed without auth"}

    def _check_directory_listing(self):
        paths = ["/images/", "/config/", "/backup/", "/log/"]
        for path in paths:
            try:
                resp = self.session.get(f"{self.base_url}{path}", timeout=self.timeout)
                if resp.status_code == 200 and "index of" in resp.text.lower():
                    print_warning(f"Directory listing enabled at {path}")
                    return {
                        "status": "FAIL",
                        "title": "Directory Listing Enabled",
                        "severity": "MEDIUM",
                        "description": f"Directory listing at {path} exposes camera files and configs."
                    }
            except:
                pass
        print_success("No directory listing found")
        return {"status": "PASS", "title": "Directory Listing", "severity": "LOW", "description": "No directory listing exposed"}

    def _demo_checks(self):
        """Demo mode results"""
        time.sleep(1)
        return [
            {"status": "FAIL", "title": "CVE-2021-36260: Hikvision RCE", "severity": "CRITICAL", "cvss": "9.8",
             "description": "Unauthenticated RCE via /SDK/webLanguage endpoint."},
            {"status": "FAIL", "title": "CVE-2017-7921: Hikvision Auth Bypass", "severity": "CRITICAL", "cvss": "9.8",
             "description": "Authentication bypass allows unauthenticated snapshot access."},
            {"status": "FAIL", "title": "Unencrypted RTSP Stream", "severity": "HIGH",
             "description": "RTSP port 554 open. Stream accessible without credentials."},
            {"status": "FAIL", "title": "Firmware Version Disclosure", "severity": "MEDIUM",
             "description": "Device info exposed without authentication."},
            {"status": "PASS", "title": "Telnet Check", "severity": "LOW",
             "description": "Telnet not exposed."},
            {"status": "PASS", "title": "Directory Listing", "severity": "LOW",
             "description": "No directory listing found."},
        ]
