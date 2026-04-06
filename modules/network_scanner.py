"""
Module 2: Network Scanner
- Local network-ൽ exposed CCTV cameras discover ചെയ്യുന്നു
- RTSP, HTTP, ONVIF ports scan ചെയ്യുന്നു
- Camera type identify ചെയ്യുന്നു
"""

import socket
import threading
import ipaddress
import time
import requests
from utils.banner import print_success, print_warning, print_error, print_info

requests.packages.urllib3.disable_warnings()

# Common CCTV ports
CCTV_PORTS = {
    80:    "HTTP Web Interface",
    443:   "HTTPS Web Interface",
    554:   "RTSP Stream",
    8080:  "HTTP Alternate",
    8443:  "HTTPS Alternate",
    8000:  "Hikvision SDK",
    8200:  "HTTP Alternate",
    37777: "Dahua SDK",
    34567: "Generic DVR",
    9000:  "Generic Camera",
}

# Brand fingerprints
BRAND_SIGNATURES = {
    "hikvision": ["hikvision", "webs", "DVRDVS-Webs", "App-webs"],
    "dahua":     ["dahua", "DahuaWeb", "Web3.0"],
    "axis":      ["axis", "AXIS", "axiscam"],
    "tplink":    ["tp-link", "tplink", "ipc"],
    "reolink":   ["reolink", "IPC"],
    "generic":   ["dvr", "nvr", "camera", "ipcam", "webcam"],
}


class NetworkScanner:
    def __init__(self, network_range=None, timeout=1):
        self.network_range = network_range
        self.timeout = timeout
        self.found_cameras = []
        self.lock = threading.Lock()

    def run_scan(self, demo=False):
        print_info("Starting Network Discovery Scan...")

        if demo:
            return self._demo_scan()

        if not self.network_range:
            self.network_range = self._get_local_network()

        print_info(f"Scanning network: {self.network_range}")
        print_info(f"Checking ports: {list(CCTV_PORTS.keys())}\n")

        try:
            network = ipaddress.ip_network(self.network_range, strict=False)
            hosts = list(network.hosts())
            print_info(f"Total hosts to scan: {len(hosts)}")

            # Limit scan to first 254 hosts for speed
            threads = []
            for ip in hosts[:254]:
                t = threading.Thread(target=self._scan_host, args=(str(ip),))
                t.daemon = True
                threads.append(t)
                t.start()
                if len(threads) % 20 == 0:
                    for thread in threads:
                        thread.join(timeout=2)
                    threads = []

            for t in threads:
                t.join(timeout=2)

        except Exception as e:
            print_error(f"Network scan error: {e}")

        return self.found_cameras

    def _scan_host(self, ip):
        open_ports = []
        for port in CCTV_PORTS.keys():
            if self._is_port_open(ip, port):
                open_ports.append(port)

        if open_ports:
            camera_info = self._identify_camera(ip, open_ports)
            with self.lock:
                self.found_cameras.append(camera_info)
                print_success(f"Camera found: {ip} | Ports: {open_ports} | Brand: {camera_info['brand']}")

    def _is_port_open(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def _identify_camera(self, ip, open_ports):
        brand = "Unknown"
        model = "Unknown"
        has_web = False

        # Try to get HTTP response for brand detection
        for port in [80, 8080, 443]:
            if port in open_ports:
                has_web = True
                try:
                    protocol = "https" if port == 443 else "http"
                    resp = requests.get(
                        f"{protocol}://{ip}:{port}",
                        timeout=3, verify=False
                    )
                    content = resp.text.lower() + str(resp.headers).lower()
                    for b, sigs in BRAND_SIGNATURES.items():
                        if any(sig.lower() in content for sig in sigs):
                            brand = b.capitalize()
                            break
                except:
                    pass
                break

        return {
            "ip": ip,
            "open_ports": open_ports,
            "brand": brand,
            "model": model,
            "has_web_interface": has_web,
            "rtsp_available": 554 in open_ports,
            "status": "FOUND"
        }

    def _get_local_network(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            # Assume /24 subnet
            parts = local_ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except:
            return "192.168.1.0/24"

    def _demo_scan(self):
        """Demo mode — simulated results"""
        print_info("Running in DEMO mode — simulated network scan\n")
        time.sleep(1)

        demo_cameras = [
            {
                "ip": "192.168.1.64",
                "open_ports": [80, 554, 8000],
                "brand": "Hikvision",
                "model": "DS-2CD2143G0-I",
                "has_web_interface": True,
                "rtsp_available": True,
                "status": "FOUND"
            },
            {
                "ip": "192.168.1.108",
                "open_ports": [80, 443, 37777],
                "brand": "Dahua",
                "model": "IPC-HDW2831T",
                "has_web_interface": True,
                "rtsp_available": False,
                "status": "FOUND"
            },
            {
                "ip": "192.168.1.220",
                "open_ports": [80, 554],
                "brand": "Generic DVR",
                "model": "Unknown",
                "has_web_interface": True,
                "rtsp_available": True,
                "status": "FOUND"
            },
        ]

        for cam in demo_cameras:
            time.sleep(0.5)
            print_success(f"Camera found: {cam['ip']} | Brand: {cam['brand']} | Ports: {cam['open_ports']}")

        return demo_cameras
