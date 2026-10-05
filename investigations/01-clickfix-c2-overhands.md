# Forensic Investigation: Kongtuke Rebuke (ClickFix Social Engineering & C2 Staging)

* **Reference Link:** [Malware Traffic Analysis - 2026-09-11 Scenario](https://malware-traffic-analysis.net/2026/09/11/index.html)
* **Environment:** Kali Linux
* **Primary Analysis Stack:** Zeek, zeek-cut, Wireshark, Tshark

---

## 1. Executive Summary

On September 11, 2026, an internal endpoint (`10.9.11.135`) within the `OVERHANDS.ORG` enterprise domain was compromised via a modern web-based social engineering campaign known as **ClickFix**. 

The user was deceived into copying an obfuscated malicious payload and executing it manually through the Windows Run prompt (`Win + R`). This triggered arbitrary code execution, established an outbound connection to external infrastructure (`104.21.91.138:443`), and opened a Command and Control (C2) channel. Network metadata extracted from Kerberos and SAMR exchanges identified the affected workstation as `DESKTOP-6T17ZFM` operated by user `gmcdowell` (Gabriel McDowell).

---

## 2. Victim Details

* **IP Address:** `10.9.11.135`
* **Host Name:** `DESKTOP-6T17ZFM`
* **Domain:** `OVERHANDS.ORG`
* **MAC Address:** `08:d4:0c:7a:29:1e` (Intel Corporate)
* **Windows User Account:** `gmcdowell`
* **User Full Name:** `Gabriel McDowell`

---

## 3. Indicators of Compromise (IOCs)

### Network Indicators

| Type | Indicator / Endpoint | Description / Protocol Context |
| :--- | :--- | :--- |
| **IPv4 / Port** | `104.21.91.138:443` (TCP) | Staging and C2 infrastructure contacted post-execution |
| **IPv4 (Internal DC)** | `10.9.11.2` (TCP/UDP) | Active Directory Domain Controller (`OVERHANDS.ORG`) |

---

## 4. Analytical Phase Breakdown & Commands

### Phase 1: Triage and Network Scoping with Zeek

#### A. Offline PCAP Processing
Zeek was executed with the `-C` flag to prevent dropped packets resulting from TCP/IP checksum offloading:
```bash
zeek -C -r /path/to/2026-09-11-traffic-analysis-exercise.pcap

```

#### B. Isolating Outbound Local Connections

Using `zeek-cut`, connection logs were parsed to isolate active hosts in the `10.9.11.0/24` subnet, excluding the Domain Controller (`10.9.11.2`):

```bash
zeek-cut id.orig_h id.resp_h id.resp_p proto < conn.log | grep "^10\.9\.11\." | grep -v "10\.9\.11\.2" | head -n 25

```

* **Finding:** Identified `10.9.11.135` generating persistent outbound sessions to public IP addresses (e.g., `104.21.91.138:443`).



#### C. Kerberos User Account Identification

Extracted authentication events from `kerberos.log`:

```bash
zeek-cut client service success < kerberos.log | sort -u

```

* **Finding:** Extracted client identity `gmcdowell/OVERHANDS.ORG` authenticating against service `host/desktop-6t17zfm.overhands.org`.



#### D. IP-to-Username Correlation

Confirmed that the account operated from the isolated IP address:

```bash
zeek-cut id.orig_h client < kerberos.log | grep "gmcdowell" | sort -u

```

* **Result:** Formally tied user `gmcdowell` to IP `10.9.11.135`.



---

### Phase 2: Deep Packet Inspection with Wireshark & Tshark

#### A. Physical MAC Address Extraction

* Filter applied:
```text
kerberos.CNameString

```


* Selected packet `71830` (`AS-REQ` sent from `10.9.11.135` to DC `10.9.11.2`).


* Expanding the **Ethernet II** frame revealed the source hardware address: **`08:d4:0c:7a:29:1e`** (`Intel_7a:29:1e`).



#### B. Hostname Verification via NetBIOS

Inspecting the Kerberos address attributes (`addresses -> HostAddress`) in the same frame exposed the NetBIOS announcement record:

* **Record:** `DESKTOP-6T17ZFM<20>` (Server service).



#### C. Full Legal Name Extraction via SAMR DCE/RPC

When directory services don't disclose `displayName` in plain LDAP queries, the Security Account Manager Remote (SAMR) protocol provides direct visibility:

* **Filter applied:**
```text
samr.samr_UserInfo21.full_name

```


* Inside the RPC structure `samr_UserInfo21` returned by the Domain Controller (`10.9.11.2`), the `Full Name` field disclosed:
* **Value:** `Gabriel McDowell`.





---

## 5. Active Directory Forensic Filter Reference

| Filter / Field | Purpose in this Investigation |
| :--- | :--- |
| `browser.command == 0x0f` | Captures Host Announcement messages from the Windows Browser Service to rapidly locate the Domain Controller. |
| `browser.response_computer_name` | Directly pulls the NetBIOS computer name from local network announcement frames. |
| `kerberos.cname_string == 1` | Isolates the principal identity in Kerberos ticket requests to retrieve the active domain username. |
| `samr.samr_UserInfo21.full_name` | Targets SAM database query responses over SMB/RPC to extract the user's registered full name. |

---

## 6. Threat Behavior & Incident Summary

| Element | Incident Detail |
| :--- | :--- |
| **Initial Access Vector** | Web social engineering / **ClickFix** lure prompting the victim to copy code into the Windows Run prompt. |
| **User Interaction** | Execution of obfuscated PowerShell commands manually triggered by the user. |
| **Impacted Host** | `DESKTOP-6T17ZFM` (`10.9.11.135` / `08:d4:0c:7a:29:1e`). |
| **Compromised User** | Gabriel McDowell (`gmcdowell`). |
| **Domain Scope** | `OVERHANDS.ORG`. |
| **Operational Impact** | Arbitrary code execution and establishment of an active C2 communication channel. |