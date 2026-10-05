# Forensic Investigation: Big Fish in a Little Pond (Win32/Koi Stealer Activity)

* **Reference Link:** [Malware Traffic Analysis - 2024-09-04 Scenario](https://malware-traffic-analysis.net/2024/09/04/index.html)
* **Environment:** Kali Linux
* **Primary Analysis Stack:** NetworkMiner (via Mono), Suricata IDS Alert Logs

---

## 1. Executive Summary

On September 4, 2024, starting at 17:35 UTC, an internal workstation (`172.17.0.99`) within the Active Directory domain `bepositive.com` was compromised by the **Win32/Koi Stealer** infostealer.

Following initial execution, the malware established unencrypted Command and Control (C2) communication directed towards a public dotted-quad IPv4 address (`79.124.78[.]197:80`). The host performed periodic HTTP `POST` check-ins and exfiltrated binary telemetry (`application/octet-stream`) to web endpoints `/foots.php` and `/index.php` while spoofing standard browser User-Agent headers. Artifact parsing via NetworkMiner confirmed the impacted host as `DESKTOP-RNVO9AT`, operated by domain user `afletcher`.

---

## 2. Victim Details

* **IP Address:** `172.17.0.99`
* **Host Name:** `DESKTOP-RNVO9AT` (FQDN: `DESKTOP-RNVO9AT.bepositive.com`)
* **Operating System:** Windows 10.0
* **MAC Address:** `18:3d:a2:b6:8d:c4` (Intel Corporate)
* **Windows User Account:** `afletcher`

---

## 3. Indicators of Compromise (IOCs)

### Network Indicators

| Type | Indicator / Endpoint | Description / Protocol Context |
| :--- | :--- | :--- |
| **IPv4 / Port** | `79.124.78[.]197:80` (TCP) | Koi Stealer Command and Control (C2) node |
| **HTTP Request (C2)** | `POST http://79.124.78[.]197/foots.php` | Telemetry exfiltration and check-in (`application/octet-stream`) |
| **HTTP Request (C2)** | `POST http://79.124.78[.]197/index.php` | Secondary beaconing and agent reporting |
| **IPv4 (Internal DC)** | `172.17.0.17` (TCP/UDP) | Active Directory Domain Controller (`win-ctl9xbq9y19.bepositive.com`) |

---

## 4. Analytical Phase Breakdown & Methods (NetworkMiner / Suricata IDS)

### Phase 1: Host Identification and Endpoint Isolation

#### A. Network Architecture and IP Scoping
* **Method Executed:** Navigated to the **Hosts** tab in NetworkMiner and sorted by the local subnet `172.17.0.0/24`.
* **Technical Evaluation:** Two active hosts were present: `172.17.0.17` (Domain Controller providing DNS and SMB/SAMR services) and `172.17.0.99` (initiating all external interactive client sessions).
* **Result:** Confirmed victim IP as **`172.17.0.99`**.

#### B. Layer 2 and OS Fingerprinting
* **Method Executed:** Expanded host properties for `172.17.0.99` in the **Hosts** tab.
* **Technical Evaluation:** NetworkMiner evaluated Ethernet II headers and TCP SYN packet fingerprints to identify hardware vendor and OS build.
* **Findings:**
  * **MAC Address:** `18:3d:a2:b6:8d:c4` (Intel Corporate).
  * **Hostname:** `DESKTOP-RNVO9AT` (`DESKTOP-RNVO9AT.bepositive.com`).
  * **Operating System:** Windows 10.0.

#### C. User Account Identification
* **Method Executed:** Inspected credentials and identity properties under node details (`User 1`).
* **Technical Evaluation:** Extracted from Active Directory Kerberos and SMB2/NTLMSSP negotiations between `172.17.0.99` and `172.17.0.17`.
* **Result:** Confirmed username **`afletcher`**.

---

### Phase 2: Traffic Inspection & Artifact Analysis

#### A. Reassembled Payloads Inspection (Files Tab)
* **Method Executed:** Sorted the **Files** tab chronologically.
* **Technical Evaluation:** Beginning at 17:35:07 UTC, observed repeated outbound `HttpPostUpload` streams ranging from 40 to 112 bytes directed to `79.124.78.197`.
* **Result:** Isolated unencrypted POST paths `/foots.php` and `/index.php` carrying `application/octet-stream` data.

#### B. IDS Alert Log Correlation (Suricata)
* **Signatures Flagged:**
  * `ET INFO GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 1` (`172.17.0.99 -> 79.124.78.197:80`)
  * `ETPRO TROJAN Win32/Koi Stealer CnC Checkin (POST) M2` (`172.17.0.99 -> 79.124.78.197:80`)
* **Technical Evaluation:** Emerging Threats signatures validated that the host was transmitting HTTP POST requests directly to an IP address without prior DNS resolution, utilizing a spoofed browser User-Agent matching **Koi Stealer** communication patterns.

---

## 5. Threat Behavior & Incident Summary

| Element | Incident Detail |
| :--- | :--- |
| **Malware Family** | **Win32/Koi Stealer** (credential infostealer trojan). |
| **Primary Objective** | Unauthorized collection and exfiltration of browser credentials, session cookies, cryptocurrency wallets, and system telemetry. |
| **C2 Infrastructure** | Direct-to-IP connection to `79.124.78[.]197:80` (TCP). |
| **Communication Mechanism** | Periodic HTTP `POST` requests to `/foots.php` and `/index.php` carrying `application/octet-stream` payloads. |
| **Compromised Host** | `DESKTOP-RNVO9AT` (IP: `172.17.0.99` / MAC: `18:3d:a2:b6:8d:c4`). |
| **Compromised User** | `afletcher` (`bepositive.com` domain). |
| **Operational Impact** | Exposure of local credentials, stolen user sessions, and potential risk of Active Directory privilege escalation. |