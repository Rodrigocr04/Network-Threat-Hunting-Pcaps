# Forensic Investigation: Lumma in the Room-ah (Lumma Stealer Telemetry & C2 Activity)

* **Reference Link:** [Malware Traffic Analysis - 2026-01-31 Scenario](https://malware-traffic-analysis.net/2026/01/31/index.html)
* **Environment:** Kali Linux
* **Primary Analysis Stack:** Zeek, zeek-cut, Wireshark, Tshark

---

## 1. Executive Summary

On January 31, 2026, an internal endpoint (`10.1.21.58`) within the Active Directory corporate environment `win11office.com` was compromised by **Lumma Stealer** (LummaC2), an infostealer engineered to harvest credentials, browser sessions, system profiles, and cryptocurrency wallets.

Following code execution, the infected host established unencrypted HTTP communications over TCP port 80 directly with external C2 infrastructure (`153.92.1.49`, associated with domain `whitepepper.su`). The malware executed client profiling check-ins via `/api/set_agent`, followed by telemetry and log exfiltration using HTTP `POST` requests (`&act=log`) while querying `/favicon.ico` as an evasion and camouflage technique. Forensic analysis of Kerberos tickets, NetBIOS broadcasts, and SAMR responses identified the affected host as `DESKTOP-ES9F3ML`, operated by user `gwyatt` (Gabriel Wyatt).

---

## 2. Victim Details

* **IP Address:** `10.1.21.58`
* **Host Name:** `DESKTOP-ES9F3ML`
* **Domain:** `win11office.com` (AD Environment: `WIN11OFFICE`)
* **MAC Address:** `00:21:5d:c8:0e:f2`
* **Windows User Account:** `gwyatt`
* **User Full Name:** `Gabriel Wyatt`

---

## 3. Indicators of Compromise (IOCs)

### Network Indicators

| Type | Indicator / Endpoint | Description / Protocol Context |
| :--- | :--- | :--- |
| **IPv4 / Port** | `153.92.1.49:80` (TCP) | Lumma Stealer Command and Control (C2) server |
| **Domain Name** | `whitepepper.su` | Host domain mapped to C2 node `153.92.1.49` |
| **HTTP Request (C2)** | `GET/POST http://whitepepper.su/api/set_agent?...` | Host fingerprinting, agent registration, and browser emulation |
| **HTTP Request (C2)** | `POST http://whitepepper.su/...&act=log` | Exfiltration of collected credentials, session cookies, and system logs |
| **HTTP Request (Camouflage)**| `GET http://whitepepper.su/favicon.ico` | Secondary evasion and heartbeat check-in requests |

---

## 4. Analytical Phase Breakdown & Commands

### Phase 1: Triage and Host Isolation with Zeek

#### A. Cross-Referencing C2 IP with Connection Logs
Using the IOC flagged in SOC alerts (`153.92.1.49`), `conn.log` was queried to identify which internal endpoint opened connections to the C2 address:
```bash
zeek-cut id.orig_h id.resp_h id.resp_p proto < conn.log | grep "153\.92\.1\.49"

```

* **Result:** Confirmed internal IP `10.1.21.58` communicating with `153.92.1.49` over TCP port 80.



#### B. Extracting Host and HTTP Activity

Inspected HTTP hostnames and URI paths contacted by the compromised endpoint:

```bash
zeek-cut id.orig_h host uri < http.log | grep "153\.92\.1\.49" | sort -u

```

* **Result:** Confirmed the destination domain `whitepepper.su` and specific API profiling paths such as `/api/set_agent?...`.



#### C. Isolating User and Machine Accounts

Parsed Kerberos ticket negotiations initiated from `10.1.21.58`:

```bash
zeek-cut id.orig_h client < kerberos.log | grep "10\.1\.21\.58" | sort -u

```

* **Client Host Principal:** `DESKTOP-ES9F3ML$` (machine account ending in `$`).


* **User Account Principal:** `gwyatt`.



---

### Phase 2: Deep Packet Dissection with Wireshark & Tshark

#### A. C2 Stream Inspection and MAC Address Extraction

Applied Wireshark display filter:

```text
ip.addr == 153.92.1.49 && http

```

* Selecting an outbound request frame to `whitepepper.su` and inspecting the **Ethernet II** header:


* **Source MAC Address:** `00:21:5d:c8:0e:f2`.




* Inspecting the HTTP payload confirmed spoofed User-Agent headers mimicking Chrome and Edge browsers alongside binary POST payloads.



#### B. Hostname Verification via NetBIOS (NBNS)

Applied display filter to isolate local NetBIOS broadcast traffic:

```text
nbns && ip.src == 10.1.21.58

```

* Packet list review displayed broadcast frame: `Registration NB DESKTOP-ES9F3ML<00>`, corroborating the NetBIOS hostname in cleartext across the local network.



#### C. Full Legal Name Extraction via SAMR / Packet Details Search

Extracted user directory attributes using string inspection on Domain Controller (`10.1.21.2`) response packets:

* Configured Wireshark search (`Ctrl + F`) targeting **Packet details**, type **String**, searching for `gwyatt`.


* Expanding the DCE/RPC response structure (`samr.samr_UserInfo21.full_name`) revealed the account display attributes:


* **Full Name:** `Gabriel Wyatt`.





---

## 5. Threat Behavior & Incident Summary

| Element | Incident Detail |
| --- | --- |
| **Malware Family** | **Lumma Stealer** (InfoStealer focused on stealing credentials, session tokens, and crypto assets).

 |
| **C2 Infrastructure** | `153.92.1.49` over TCP port 80.

 |
| **Involved Domain** | `whitepepper.su`.

 |
| **Activity Pattern / Beacons** | Emulated browser HTTP requests to `/api/set_agent?...`, POST uploads with `&act=log`, and requests to `/favicon.ico`.

 |
| **Compromised Host** | `DESKTOP-ES9F3ML` (IP: `10.1.21.58` / MAC: `00:21:5d:c8:0e:f2`).

 |
| **Compromised User** | Gabriel Wyatt (Account: `gwyatt`).

 |
| **Affected Domain** | `win11office.com` (`WIN11OFFICE`).

 |
| **Operational Impact** | Covert harvesting and exfiltration of browser data, session cookies, and local credentials, exposing corporate network assets.