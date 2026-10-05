# Forensic Investigation: Easy as 123 (NetSupport Manager RAT Activity)

* **Reference Link:** [Malware Traffic Analysis - 2026-02-28 Scenario](https://malware-traffic-analysis.net/2026/02/28/index.html)
* **Environment:** Kali Linux
* **Primary Analysis Stack:** Zeek, zeek-cut, Wireshark, Tshark

---

## 1. Executive Summary

On February 28, 2026, an internal endpoint (`10.2.28.88`) within the Active Directory domain `EASYAS123.TECH` was compromised by **NetSupport Manager RAT**, a known remote access trojan derived from legitimate remote administration commercial software.

Following initial execution, the compromised workstation established an unencrypted command and control (C2) channel towards external infrastructure (`45.131.214.85`). The malware continuously sent HTTP `POST` requests to `/fakeurl.htm`, transmitting client telemetry, registration markers, and agent system information. Network forensics and Active Directory artifact parsing identified the affected machine as `DESKTOP-TEYQ2NR`, operated by domain user `brolf` (Becka Rolf).

---

## 2. Victim Details

* **IP Address:** `10.2.28.88`
* **Host Name:** `DESKTOP-TEYQ2NR`
* **Domain:** `EASYAS123.TECH` (AD Environment: `EASYAS123`)
* **MAC Address:** `00:19:d1:b2:4d:ad`
* **Windows User Account:** `brolf`
* **User Full Name:** `Becka Rolf`

---

## 3. Indicators of Compromise (IOCs)

### Network Indicators

| Type | Indicator / Endpoint | Description / Protocol Context |
| :--- | :--- | :--- |
| **IPv4 / Port** | `45.131.214.85:80` / `45.131.214.85:443` (TCP) | NetSupport Manager RAT Command and Control (C2) server |
| **HTTP Request (C2)** | `POST http://45.131.214.85/fakeurl.htm` | Registration beacon, agent check-in, and telemetry reporting |

---

## 4. Analytical Phase Breakdown & Commands

### Phase 1: Triage and Host Isolation with Zeek

#### A. IOC Cross-Referencing in Connection Logs
Using the external C2 IP provided by SOC triage alerts (`45.131.214.85`), `conn.log` was queried to identify which internal endpoint initiated the connection:
```bash
zeek-cut id.orig_h id.resp_h id.resp_p proto < conn.log | grep "45\.131\.214\.85"

```

* **Result:** Uncovered direct communications originating from local endpoint `10.2.28.88` towards the external C2 address.



#### B. Isolating User and Machine Accounts

Queried Kerberos authentication logs filtering by the compromised workstation IP:

```bash
zeek-cut id.orig_h client < kerberos.log | grep "10\.2\.28\.88" | sort -u

```

* **Host Principal:** `DESKTOP-TEYQ2NR$` (machine account ending in `$`).


* **User Principal:** `brolf`.


* **Domain Realm:** `EASYAS123.TECH` / `EASYAS123`.



---

### Phase 2: Deep Packet Dissection with Wireshark & Tshark

#### A. Temporal Correlation and Physical MAC Extraction

Applied Wireshark display filter:

```text
ip.addr == 10.2.28.88 && frame.time >= "2026-02-28 19:55:00"

```

* Inspecting outbound frames sent towards the gateway and the local subnet under the **Ethernet II** header:


* **Source MAC Address:** `00:19:d1:b2:4d:ad`.





#### B. C2 Beacon Validation and Network Announcements

* **HTTP Traffic Inspection:**
* Observed cleartext HTTP `POST` requests directed to `http://45.131.214.85/fakeurl.htm`, a signature artifact of NetSupport Manager RAT beaconing behavior.




* **NetBIOS / BROWSER Broadcasts:**
* Protocol messages `Request Announcement DESKTOP-TEYQ2NR` and `Browser Election Request` confirmed the hostname `DESKTOP-TEYQ2NR` in cleartext within subnet `10.2.28.0/24`.





#### C. Full Legal Name Extraction via SAMR (Headless CLI Parsing)

When standard LDAP fields do not expose user names due to binary RPC/NDR packaging, SAMR interface queries over DCE/RPC provide the exact user attribute:

```bash
tshark -r /path/to/2026-02-28-traffic-analysis-exercise.pcap \
  -Y "samr.samr_UserInfo21.full_name" \
  -T fields -e samr.samr_UserInfo21.full_name | sort -u

```

* **Field Decoded:** `samr.samr_UserInfo21.full_name`.


* **Result:** Confirmed the victim's full legal name as **Becka Rolf**.



---

## 5. Threat Behavior & Incident Summary

| Element | Incident Detail |
| --- | --- |
| **Malware Family** | **NetSupport Manager RAT** (Remote Access Trojan leveraging modified commercial administration software).

 |
| **C2 Infrastructure** | `45.131.214.85` (HTTP / port 443 / port 80).

 |
| **Beacon / Activity Signature** | Periodic HTTP `POST` requests to `/fakeurl.htm` containing agent telemetry headers and operational check-ins.

 |
| **Compromised Host** | `DESKTOP-TEYQ2NR` (IP: `10.2.28.88` / MAC: `00:19:d1:b2:4d:ad`).

 |
| **Compromised User** | Becka Rolf (Account: `brolf`).

 |
| **Affected Domain** | `EASYAS123.TECH` (`EASYAS123`).

 |
| **Operational Impact** | Full endpoint compromise enabling arbitrary command execution, screen capturing, file manipulation, and covert remote control.