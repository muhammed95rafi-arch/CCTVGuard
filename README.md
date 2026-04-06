# CCTVGuard 🛡️

A professional CCTV Security Assessment Tool built for SOC analysts and penetration testers to identify vulnerabilities in IP cameras and DVR systems.

## Features

- Network Discovery — Scans local network for exposed CCTV cameras
- Vulnerability Assessment — Checks for known CVEs (Hikvision, Dahua, D-Link)
- Default Password Scanner — Tests common default credentials
- Report Generator — Generates HTML and TXT reports
- Demo Mode — Test the tool without a real target

## Installation

git clone https://github.com/muhammed95rafi-arch/CCTVGuard.git
cd CCTVGuard
pip install -r requirements.txt

## Usage

python3 main.py --demo
python3 main.py --target 192.168.1.64
python3 main.py --target 192.168.1.64 --brand hikvision
python3 main.py --network 192.168.1.0/24

## Supported Brands

- Hikvision
- Dahua
- Axis
- TP-Link
- Reolink
- Generic DVR/NVR

## CVEs Covered

- CVE-2021-36260 — Hikvision RCE (CVSS 9.8)
- CVE-2017-7921 — Hikvision Auth Bypass (CVSS 9.8)
- CVE-2019-9082 — Dahua Auth Bypass (CVSS 9.8)
- CVE-2021-33044 — Dahua Identity Bypass (CVSS 9.8)
- CVE-2018-9995 — Generic DVR Auth Bypass (CVSS 9.8)
- CVE-2020-25078 — D-Link Credential Disclosure (CVSS 7.5)

## Legal Disclaimer

This tool is for educational and authorized security testing only.
Only test cameras you own or have explicit permission to test.
Unauthorized use is illegal and unethical.

## Author

Muhammad Khan
Certified Penetration Tester (CPT)
HackerOne — High Severity Bug Bounty Hunter (CVSS 7.5)
GitHub: github.com/muhammed95rafi-arch
