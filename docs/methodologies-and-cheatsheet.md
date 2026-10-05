# Network Forensics & Threat Hunting Methodologies & Cheatsheet

This reference document outlines the analytical workflows, protocol heuristics, and command cheatsheet used across the investigations in this repository to profile compromised endpoints, isolate Command and Control (C2) activity, and extract threat intelligence from raw PCAP datasets.

---

## 🎯 Analytical Workflow Overview

When analyzing a full-packet capture of an unknown intrusion, follow a consistent 3-stage triage model:

```text
┌────────────────────────────────────────┐
│  Phase 1: Subnet Scoping & Triage      │
│  - Isolate active hosts (/24 CIDR)     │
│  - Filter Domain Controllers & Gateways│
│  - Identify anomalous external traffic │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│  Phase 2: AD Identity Profiling        │
│  - Resolve MAC address (Layer 2)       │
│  - Extract Hostname (NBNS / Kerberos)  │
│  - Determine Username (Kerberos/SAMR)  │
│  - Extract Full Name (SAMR DCE/RPC)    │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│  Phase 3: Threat Characterization & C2 │
│  - Reconstruct initial access lure     │
│  - Detect beaconing intervals & URIs   │
│  - Inspect unencrypted payloads        │
│  - Correlate with IDS/Suricata alerts  │
└────────────────────────────────────────┘

```

---

## 🔍 Phase 1: Subnet Scoping & Traffic Baseline

### 1. Identifying the Victim Workstation

Corporate environments generate heavy automated background traffic (NTP, DNS, NCSI, Windows Update). To locate the victim:

1. Identify the internal broadcast/gateway (`.1`, `.2`, or `.3`) and Active Directory Domain Controllers.
2. Filter for hosts initiating non-standard HTTP/HTTPS traffic towards external public IP addresses.

#### Using Tshark:

```bash
# Filter outbound web traffic originating from local clients (e.g., 10.1.17.0/24)
tshark -r capture.pcap -Y "ip.src >= 10.1.17.3 and ip.src <= 10.1.17.254 and (http.request or tls.handshake.type == 1)" \
  -T fields -e ip.src | sort | uniq -c | sort -nr

```

#### Using Zeek / Zeek-cut:

```bash
# Process PCAP offline ignoring bad checksums
zeek -C -r capture.pcap

# Inspect outbound connections from the local scope excluding the Domain Controller
zeek-cut id.orig_h id.resp_h id.resp_p proto < conn.log | grep "^10\.9\.11\." | grep -v "10\.9\.11\.2" | head -n 30

```

#### Using Zui (Zed Engine):

```zed
_path=="conn" | id.orig_h >= 10.11.26.4 and id.orig_h <= 10.11.26.254 | count() by id.orig_h

```

---

## 👤 Phase 2: Active Directory Identity Profiling

Active Directory identity attribution can be extracted directly from raw protocol exchanges without requiring access to Security Event Logs (Event ID 4624).

### 1. MAC Address (Layer 2 Hardware ID)

* **Wireshark Display Filter:** `ip.src == <VICTIM_IP>` -> Inspect the `Source` field inside the **Ethernet II** header.
* **Tshark CLI:**
```bash
tshark -r capture.pcap -Y "ip.src == <VICTIM_IP>" -T fields -e eth.src | sort -u

```



### 2. Hostname Resolution

* **Via NetBIOS Name Service (NBNS):** Windows machines broadcast registration packets upon joining or announcing services to the local subnet.
* **Wireshark Display Filter:** `nbns && ip.src == <VICTIM_IP>`
* Look for: `Registration NB <HOSTNAME><00>` in the Info column.


* **Via Kerberos Machine Accounts:** Computer objects authenticate against the KDC using an account name ending in `$`.
* **Tshark CLI:**
```bash
tshark -r capture.pcap -Y 'ip.src == <VICTIM_IP> and kerberos.CNameString contains "$"' -T fields -e kerberos.CNameString | sort -u

```




* **Via Windows Browser Service:**
* `browser.command == 0x0f` (Host Announcement).
* `browser.response_computer_name` (Extracts computer name field).



### 3. Domain Username Attribution

* **Via Kerberos Client Authentication:**
* When a domain user requests a Ticket Granting Ticket (`AS-REQ`), the principal name appears in `CNameString`.
* **Wireshark Display Filter:** `kerberos.cname_string`
* **Tshark CLI:**
```bash
tshark -r capture.pcap -Y 'ip.src == <VICTIM_IP> and kerberos.CNameString and !(kerberos.CNameString contains "$")' -T fields -e kerberos.CNameString | sort -u

```


* **Zeek CLI:**
```bash
zeek-cut id.orig_h client < kerberos.log | grep "<VICTIM_IP>" | sort -u

```





### 4. Full Legal Name (DCE/RPC via SAMR)

When LDAP queries are encrypted or display names are obfuscated, Windows workstations query user details from the Security Account Manager Remote (SAMR) protocol over SMB (TCP port 445).

* **Wireshark Display Filter:**
```text
samr.samr_UserInfo21.full_name

```


* **Tshark CLI:**
```bash
tshark -r capture.pcap -Y "samr.samr_UserInfo21.full_name" -T fields -e samr.samr_UserInfo21.full_name | sort -u

```



---

## 🚨 Phase 3: Threat Identification & C2 Beaconing Heuristics

### 1. Differentiating Legitimate Traffic from Malware C2

* **NCSI False Positives:** Windows checks internet connectivity by requesting `http://www.msftconnecttest.com/connecttest.txt` or `ipv6.msftconnecttest.com`. Filter these out during triage.
* **Direct-to-IP HTTP Requests:** Legitimate web traffic typically relies on DNS resolution. Outbound HTTP requests directed straight to a public dotted quad (without prior DNS resolution) strongly suggest hardcoded malware C2 nodes.
* **Anomalous Ports:** Raw, unencrypted HTTP traffic communicating over TCP port 443 (typically reserved for TLS) is a common evasion technique used by RATs (e.g., NetSupport).

### 2. HTTP Beaconing & Telemetry Extraction

```bash
# Isolate external HTTP requests excluding Microsoft / OS noise
tshark -r capture.pcap -Y 'http.request and !(http.host contains "microsoft" or http.host contains "windowsupdate" or http.host contains "msftconnecttest")' \
  -T fields -e frame.time -e ip.dst -e http.request.method -e http.host -e http.request.uri | sort -u

```

### 3. TLS Server Name Indication (SNI) Inspection

For traffic routed over HTTPS where payload inspection is encrypted:

```bash
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e frame.time -e ip.dst -e tls.handshake.extensions_server_name | sort -u

```

---

## ⚡ Network Port Reference for Forensics

| Port | Protocol | Default Service | Forensic & Incident Context |
| --- | --- | --- | --- |
| **53** | UDP/TCP | DNS | Pre-infection domain lookups, fast-flux domains, DGA resolution. |
| **67/68** | UDP | DHCP | IP lease assignments; Option 12 reveals client hostname. |
| **80** | TCP | HTTP | Unencrypted web traffic, second-stage drops, raw C2 beaconing. |
| **88** | TCP/UDP | Kerberos | AD authentication tickets (`AS-REQ`, `TGS-REQ`); source of usernames and hostnames. |
| **137/138** | UDP | NetBIOS (NBNS) | Local name registration and name querying within legacy AD environments. |
| **139** | TCP | NetBIOS Session | Legacy SMB session transport; NetBIOS setup over TCP. |
| **389/636** | TCP | LDAP / LDAPS | Active Directory queries, object enumeration, user directory lookups. |
| **443** | TCP | HTTPS / TLS | Encrypted web traffic; inspected via SNI fields and certificates. |
| **445** | TCP | SMB over IP | File sharing, SAMR account queries, and lateral movement detection. |
| **3389** | TCP | RDP | Interactive remote desktop access, lateral movement, unauthorized admin sessions. |