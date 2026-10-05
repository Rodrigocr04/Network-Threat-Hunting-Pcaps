# Forensic Investigation: Nemotodes (NetSupport RAT & ZPHP / FakeUpdates Delivery)

* **Reference Link:** [Malware Traffic Analysis - 2024-11-26 Scenario](https://malware-traffic-analysis.net/2024/11/26/index.html)
* **Environment:** Kali Linux
* **Primary Analysis Stack:** Zui (Zed Engine), Tshark, Suricata IDS Alert Logs

---

## 1. Executive Summary

On November 26, 2024, an endpoint (`10.11.26.183`) operating within the `nemotodes.health` research domain was compromised via the **ZPHP / FakeUpdates** malware distribution pipeline.

The user browsed to a compromised website distributing fraudulent software packages (`modandcrackedapk[.]com`), retrieving a deceptive stage-1 loader. Following execution, the endpoint detonated **NetSupport Manager RAT**. The RAT established command and control (C2) by routing unencrypted HTTP `POST` requests to `/fakeurl.htm` directly over TCP port 443 towards `194.180.191[.]64` (bypassing conventional TLS inspection) and queried `geo.netsupportsoftware[.]com` to geolocate the victim system. Correlating Kerberos and network metadata confirmed the impacted machine as `DESKTOP-B8TQK49`, operated by user `oboomwald`.

---

## 2. Victim Details

* **IP Address:** `10.11.26.183`
* **Host Name:** `DESKTOP-B8TQK49`
* **Domain:** `nemotodes.health`
* **MAC Address:** `d0:57:7b:ce:fc:8b`
* **Windows User Account:** `oboomwald`

---

## 3. Indicators of Compromise (IOCs)

### Network Indicators

| Type | Indicator / Endpoint | Description / Protocol Context |
| :--- | :--- | :--- |
| **Domain / FQDN** | `modandcrackedapk[.]com` | Initial delivery lure / FakeUpdates (ZPHP) site (`193.42.38[.]139:443`) |
| **IPv4 / Port** | `194.180.191[.]64:443` (TCP) | NetSupport RAT Command and Control (C2) node |
| **HTTP Request (C2)** | `POST http://194.180.191[.]64:443/fakeurl.htm` | Unencrypted C2 beaconing and telemetry over port 443 |
| **FQDN / API** | `geo.netsupportsoftware[.]com` | Legitimate service queried by RAT for IP geolocation profiling |

---

## 4. Analytical Phase Breakdown & Commands (Zui / Tshark)

### Phase 1: Endpoint Identification and Subnet Scoping

#### A. Scoping Local Subnet Traffic
Evaluated connection flows across subnet `10.11.26.0/24`, excluding the gateway (`10.11.26.1`) and Domain Controller (`10.11.26.3`):

* **Zui Query (Zed):**
  ```zed
  _path=="conn" | id.orig_h >= 10.11.26.4 and id.orig_h <= 10.11.26.254 | count() by id.orig_h

```

* **Tshark CLI Alternative:**
```bash
tshark -r 2024-11-26-traffic-analysis-exercise.pcap \
  -Y "ip.src >= 10.11.26.4 and ip.src <= 10.11.26.254 and (http.request or tls.handshake.type == 1)" \
  -T fields -e ip.src | sort | uniq -c | sort -nr

```


* **Result:** Confirmed `10.11.26.183` as the sole client originating anomalous external web traffic.



#### B. Physical MAC Address Extraction

Retrieved the source hardware address for frames originating from the victim IP:

```bash
tshark -r 2024-11-26-traffic-analysis-exercise.pcap -Y "ip.src == 10.11.26.183" -T fields -e eth.src | sort -u

```

* **Result:** Confirmed MAC address: `d0:57:7b:ce:fc:8b`.



---

### Phase 2: Active Directory Identity Resolution

#### A. Hostname Extraction via Kerberos

Inspected Kerberos ticket service requests emitted by `10.11.26.183`:

* **Zui Query (Zed):**
```zed
_path=="kerberos" | id.orig_h == 10.11.26.183 | cut client, service

```


* **Result:** Service ticket reference `host/desktop-b8tqk49.nemotodes.health` established the machine hostname as **`DESKTOP-B8TQK49`**.



#### B. Domain Username Extraction

Filtered out machine accounts (ending in `$`) to isolate interactive user sessions:

* **Zui Query (Zed):**
```zed
_path=="kerberos" | id.orig_h == 10.11.26.183 | client !~ /\$/ | cut client

```


* **Tshark CLI Alternative:**
```bash
tshark -r 2024-11-26-traffic-analysis-exercise.pcap \
  -Y 'ip.src == 10.11.26.183 and kerberos.CNameString and !(kerberos.CNameString contains "$")' \
  -T fields -e kerberos.CNameString | sort -u

```


* **Result:** Identified interactive domain account: **`oboomwald`** (`oboomwald/NEMOTODES.HEALTH`).



---

### Phase 3: Infection Vector & C2 Beaconing Analysis

#### A. Staging & Delivery Lure (ZPHP)

Audited TLS Server Name Indication (SNI) records preceding the infection:

* **Zui Query (Zed):**
```zed
_path=="ssl" | id.orig_h == 10.11.26.183 | cut ts, id.resp_h, server_name

```


* **Finding:** At 04:50:14 UTC, multiple TLS handshakes were initiated towards `modandcrackedapk[.]com` (`193.42.38[.]139`), triggering the stage-1 infection.



#### B. NetSupport RAT C2 & Evasion Mechanics

Inspected application-layer web activity:

* **Zui Query (Zed):**
```zed
_path=="http" | id.orig_h == 10.11.26.183 | cut id.resp_h, host, method, uri, status_code

```


* **Correlated IDS Signatures (Suricata):**
* `ET CURRENT_EVENTS ZPHP Domain in DNS Lookup / TLS SNI (modandcrackedapk.com)`

* `ET POLICY HTTP traffic on port 443 (POST) -> 194.180.191.64`

* `ETPRO TROJAN NetSupport RAT CnC Activity -> 194.180.191.64`

* `ET POLICY NetSupport GeoLocation Lookup Request -> geo.netsupportsoftware.com`



* **Analysis:** The malware communicated with `194.180.191[.]64` over TCP port 443 using cleartext HTTP `POST` requests directed to `/fakeurl.htm` (an evasion method avoiding TLS encryption while abusing standard SSL port allowances), followed by a query to `geo.netsupportsoftware[.]com/location/loca.asp` for victim geolocation.



---

## 5. Threat Behavior & Incident Summary

| Element | Incident Detail |
| :--- | :--- |
| **Initial Access Vector** | Drive-by delivery via fake cracked application lure (`modandcrackedapk[.]com`) associated with the ZPHP/FakeUpdates campaign. |
| **Malware Family** | **NetSupport RAT** (commercial remote administration client abused as a backdoor). |
| **C2 Protocol & Port** | Unencrypted HTTP `POST` traffic over TCP port 443 targeting `/fakeurl.htm` at `194.180.191[.]64`. |
| **Telemetry Profiling** | Public IP and geographic discovery via `geo.netsupportsoftware[.]com/location/loca.asp`. |
| **Compromised Host** | `DESKTOP-B8TQK49` (IP: `10.11.26.183` / MAC: `d0:57:7b:ce:fc:8b`). |
| **Compromised User** | `oboomwald` (`nemotodes.health`). |
| **Operational Impact** | Unauthorized remote interactive control, screen viewing, keystroke logging, and potential lateral movement across the enterprise network. |