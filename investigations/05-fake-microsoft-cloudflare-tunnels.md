# Forensic Investigation: It's a Trap! (Typosquatting & Cloudflare Tunnel C2)

* **Reference Link:** [Malware Traffic Analysis - 2025-06-13 Scenario](https://malware-traffic-analysis.net/2025/06/13/index.html)
* **Environment:** Kali Linux
* **Primary Analysis Stack:** Wireshark, Tshark

---

## 1. Executive Summary

On June 13, 2025, an endpoint (`10.6.13.133`) within an enterprise Active Directory environment was compromised following interaction with an external malicious landing website (`hillcoweb[.]com`).

Immediately after the initial web encounter, the infected host established continuous, unencrypted HTTP Command and Control (C2) communications over TCP port 80. The threat actor leveraged typosquatting infrastructure mimicking legitimate Microsoft services (`event-time-microsoft[.]org`, `eventdata-microsoft[.]live`, and `windows-msgas[.]com`), as well as dynamic proxy endpoints hosted behind Cloudflare tunnels (`varying-rentals-calgary-predict.trycloudflare[.]com`). Network layer forensics, NetBIOS broadcasts, and DCE/RPC SAMR queries identified the compromised machine as `DESKTOP-5AVE44C`, operated by user `rgaines` (Roman Gaines).

---

## 2. Victim Details

* **IP Address:** `10.6.13.133`
* **Host Name:** `DESKTOP-5AVE44C`
* **MAC Address:** `24:77:03:ac:97:df`
* **Windows User Account:** `rgaines`
* **User Full Name:** `Roman Gaines`

---

## 3. Indicators of Compromise (IOCs)

### Network Indicators

| Type | Indicator / Endpoint | Description / Protocol Context |
| :--- | :--- | :--- |
| **Domain / FQDN** | `hillcoweb[.]com` | Initial delivery lure / stage-1 intermediate web redirect |
| **Domain / FQDN** | `event-time-microsoft[.]org` | Typosquatting C2 node (HTTP / TCP port 80) |
| **Domain / FQDN** | `eventdata-microsoft[.]live` | Typosquatting C2 node (HTTP / TCP port 80) |
| **Domain / FQDN** | `windows-msgas[.]com` | Typosquatting C2 node (HTTP / TCP port 80) |
| **Domain / FQDN** | `varying-rentals-calgary-predict.trycloudflare[.]com` | Ephemeral Cloudflare tunnel used to obfuscate backend C2 IP |
| **HTTP Request (C2)** | `POST /<pseudo-random-path>` | Periodic beaconing and telemetry exfiltration carrying encoded query strings |

---

## 4. Analytical Phase Breakdown & Commands

### Phase 1: Triage and Malicious Web Traffic Isolation

#### A. Filtering HTTP Requests and TLS Client Hellos
To identify suspicious web browsing activity while eliminating network noise, the following display filter was applied in Wireshark:
```text
(http.request or tls.handshake.type eq 1) and !(ssdp)

```

* **Filter Explanation:**
* `http.request`: Isolates all cleartext web requests (methods `GET`, `POST`).


* `tls.handshake.type eq 1`: Isolates TLS `Client Hello` frames, exposing the Server Name Indication (SNI).


* `and !(ssdp)`: Excludes Simple Service Discovery Protocol multimedia broadcasts on UDP port 1900.




* **Observation:** The timeline captured outbound handshakes towards `hillcoweb[.]com`, immediately succeeded by persistent unencrypted HTTP bursts to spoofed Microsoft domains.



#### B. C2 Infrastructure Heuristics

The outbound traffic exhibited multiple threat indicators:

1. **Typosquatting & Brand Spoofing:** Domains such as `event-time-microsoft[.]org` and `eventdata-microsoft[.]live` imitated authentic operating system update services, but resolved to Cloudflare infrastructure rather than official Microsoft IP ranges.


2. **Anomalous Port Usage:** Communications were conducted via plain HTTP over TCP port 80 instead of modern encrypted HTTPS standards (TCP port 443).


3. **Beaconing & Dynamic URIs:** Continuous HTTP `POST` requests were observed transmitting encoded telemetry parameters over randomized URI paths.


4. **Cloudflare Tunnels:** Tunneling traffic through `trycloudflare[.]com` hid the actual public IP address of the threat actor's command server.



---

### Phase 2: Active Directory Identity Profiling

#### A. IP and MAC Address Confirmation

* **IP Address:** Identified as `10.6.13.133` from the `Source` column across outbound C2 packets.


* **Hardware Address:** Expanding the **Ethernet II** header of packets originated by the victim revealed the physical address:


* **Source MAC:** `24:77:03:ac:97:df`.





#### B. Hostname Identification via NetBIOS (NBNS)

Applied the filter:

```text
nbns && ip.src == 10.6.13.133

```

* **Finding:** NetBIOS name registration broadcasts displayed `Registration NB DESKTOP-5AVE44C<00>`, establishing the hostname as **`DESKTOP-5AVE44C`**.



#### C. User Account and Full Name Extraction

* **Full Name via SAMR:**
* Evaluated DCE/RPC responses from the Domain Controller using:
```text
samr.samr_UserInfo21.full_name

```


* Disclosed the real identity: **Roman Gaines**.




* **Username:** Domain authentication and directory lookups associated with this user revealed the active account name: **`rgaines`**.



---

## 5. Threat Behavior & Incident Summary

| Element | Incident Detail |
| --- | --- |
| **Initial Infection Vector** | Web browsing to malicious landing domain `hillcoweb[.]com`, triggering stage-1 script delivery.

 |
| **C2 Infrastructure** | Distributed typosquatting domains mimicking Microsoft (`event-time-microsoft[.]org`, `windows-msgas[.]com`) and trycloudflare tunnels.

 |
| **C2 Protocol & Transport** | Persistent cleartext HTTP `POST` requests over TCP port 80 carrying pseudo-random parameters.

 |
| **Evasion Tactics** | Reverse proxying via Cloudflare CDN and masquerading under Microsoft naming conventions.

 |
| **Compromised Host** | `DESKTOP-5AVE44C` (IP: `10.6.13.133` / MAC: `24:77:03:ac:97:df`).

 |
| **Compromised User** | Roman Gaines (`rgaines`).

 |
| **Operational Impact** | Installation of an interactive agent capable of persistent beaconing, remote execution, and telemetry exfiltration.