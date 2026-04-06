#!/usr/bin/env python3
"""
CCTVGuard — CCTV Security Assessment Tool
SOC Portfolio Project

Usage:
  python3 main.py --demo
  python3 main.py --target 192.168.1.64
  python3 main.py --target 192.168.1.64 --brand hikvision
  python3 main.py --target 192.168.1.64 --brand dahua --port 8080
  python3 main.py --network 192.168.1.0/24
"""

import argparse
import sys
import time

from utils.banner import (print_banner, print_section,
                           print_success, print_warning,
                           print_error, print_info, print_critical)
from utils.logger import setup_logger, log_finding
from modules.network_scanner import NetworkScanner
from modules.password_scanner import DefaultPasswordScanner
from modules.vuln_checker import VulnerabilityChecker
from modules.report_generator import generate_report


def parse_args():
    parser = argparse.ArgumentParser(
        description="CCTVGuard — CCTV Security Assessment Tool"
    )
    parser.add_argument("--target",  "-t", help="Target camera IP (e.g. 192.168.1.64)")
    parser.add_argument("--brand",   "-b", help="Camera brand: hikvision/dahua/axis/tplink/reolink/generic",
                        default="generic")
    parser.add_argument("--port",    "-p", help="HTTP port (default: 80)", type=int, default=80)
    parser.add_argument("--network", "-n", help="Network range to scan (e.g. 192.168.1.0/24)")
    parser.add_argument("--https",   action="store_true", help="Use HTTPS")
    parser.add_argument("--demo",    action="store_true", help="Run demo mode")
    parser.add_argument("--skip-network",  action="store_true", help="Skip network scan")
    parser.add_argument("--skip-password", action="store_true", help="Skip password scan")
    parser.add_argument("--skip-vuln",     action="store_true", help="Skip vulnerability check")
    return parser.parse_args()


def confirm_auth(target):
    print_warning("AUTHORIZATION CHECK")
    print_warning(f"Target: {target}")
    print_warning("Only test cameras you OWN or have explicit permission to test.")
    confirm = input("\n  Do you have authorization? (yes/no): ").strip().lower()
    if confirm != "yes":
        print_error("Aborted — Authorization not confirmed.")
        sys.exit(0)
    print_success("Authorization confirmed.\n")
    time.sleep(0.5)


def calculate_risk(password_results, vuln_results):
    score = 0
    sev_scores = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}

    # Password findings
    if password_results.get("vulnerable"):
        score += 10  # Default creds = instant critical

    # Vuln findings
    for v in vuln_results:
        if v["status"] == "FAIL":
            score += sev_scores.get(v["severity"], 0)

    return min(score, 100)


def main():
    print_banner()
    args = parse_args()
    logger, log_file = setup_logger()

    network_cameras  = []
    vuln_results     = []
    password_results = {"vulnerable": False, "credentials_found": [], "findings": []}
    risk_score       = 0
    target_label     = args.target or args.network or "demo-camera.local"

    if args.demo:
        print_info("Running in DEMO mode — simulated results\n")
        target_label = "192.168.1.64 (Demo)"
    elif not args.target and not args.network:
        print_error("Please provide --target IP or --network range")
        print_info("Example: python3 main.py --target 192.168.1.64")
        print_info("Demo:    python3 main.py --demo")
        sys.exit(1)
    else:
        confirm_auth(args.target or args.network)

    # ── Module 1: Network Discovery ──────────────────────────────
    if not args.skip_network:
        print_section("MODULE 1: NETWORK DISCOVERY")
        scanner = NetworkScanner(
            network_range=args.network,
            timeout=1
        )
        network_cameras = scanner.run_scan(demo=args.demo)
        print_info(f"\nCameras Found: {len(network_cameras)}")
        for cam in network_cameras:
            log_finding(logger, "HIGH" if cam.get("rtsp_available") else "MEDIUM",
                       f"Camera: {cam['ip']}", f"Brand: {cam['brand']}")

    # ── Module 2: Vulnerability Check ────────────────────────────
    if not args.skip_vuln:
        print_section("MODULE 2: VULNERABILITY ASSESSMENT")
        target_ip = args.target or (network_cameras[0]["ip"] if network_cameras else "192.168.1.64")
        checker = VulnerabilityChecker(
            target_ip=target_ip,
            port=args.port,
            brand=args.brand,
            use_https=args.https
        )
        vuln_results = checker.run_checks(demo=args.demo)

        critical = sum(1 for v in vuln_results if v["severity"] == "CRITICAL" and v["status"] == "FAIL")
        high     = sum(1 for v in vuln_results if v["severity"] == "HIGH"     and v["status"] == "FAIL")
        print_info(f"\nVulnerabilities — Critical: {critical} | High: {high}")

    # ── Module 3: Default Password Scan ──────────────────────────
    if not args.skip_password:
        print_section("MODULE 3: DEFAULT PASSWORD SCAN")
        target_ip = args.target or (network_cameras[0]["ip"] if network_cameras else "192.168.1.64")

        if args.demo:
            print_info("Demo: Testing default credentials...")
            time.sleep(1)
            print_critical("Demo Result: Default credentials admin:12345 FOUND!")
            password_results = {
                "target": target_ip,
                "vulnerable": True,
                "credentials_found": ["admin:12345"],
                "findings": [{
                    "status": "FAIL",
                    "title": "Default Credentials: admin:12345",
                    "severity": "CRITICAL",
                    "description": "Camera accessible with default credentials. Change immediately!"
                }]
            }
        else:
            pw_scanner = DefaultPasswordScanner(
                target_ip=target_ip,
                port=args.port,
                brand=args.brand,
                use_https=args.https
            )
            password_results = pw_scanner.run_scan()

    # ── Risk Score ────────────────────────────────────────────────
    risk_score = calculate_risk(password_results, vuln_results)

    # ── Module 4: Report ──────────────────────────────────────────
    print_section("MODULE 4: GENERATING REPORT")
    html_path, txt_path = generate_report(
        target=target_label,
        network_cameras=network_cameras,
        vuln_results=vuln_results,
        password_results=password_results,
        risk_score=risk_score
    )
    print_success(f"HTML Report → {html_path}")
    print_success(f"TXT  Report → {txt_path}")

    # ── Summary ───────────────────────────────────────────────────
    print_section("ASSESSMENT COMPLETE")
    from modules.report_generator import _risk_level
    print_info(f"Risk Score  : {risk_score}/100")
    print_info(f"Risk Level  : {_risk_level(risk_score)}")
    print_info(f"Cameras Found : {len(network_cameras)}")
    print_info(f"Log File    : {log_file}")
    print()
    print_warning("Key Takeaways:")
    print_info("• Change default passwords on ALL cameras immediately")
    print_info("• Disable Telnet, HTTP — use HTTPS only")
    print_info("• Apply firmware patches for known CVEs")
    print_info("• Use VPN for remote access — never port forward cameras")
    print_info("• Segment cameras on separate VLAN")


if __name__ == "__main__":
    main()
