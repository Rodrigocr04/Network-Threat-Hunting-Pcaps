# Tooling Setup, Environment Configuration & Tool Playbooks

This guide documents the installation procedures, runtime bug workarounds, and command execution playbooks for the tooling stack deployed in **Kali Linux**.

---

## 🛠️ Installation & Environment Setup

### 1. Wireshark & Tshark
Standard suite for graphical and headless packet dissection.

**Installation:**
```bash
sudo apt update
sudo apt install wireshark tshark -y

```

**Non-Root Packet Capture Permissions:**

```bash
sudo usermod -aG wireshark $USER
newgrp wireshark

```

---

### 2. Zeek (Bro Network Security Monitor)

Generates high-fidelity connection and application protocol metadata logs.

**Installation:**

```bash
sudo apt update
sudo apt install zeek zeek-aux -y

```

**Checksum Execution Flag:**
Always pass `-C` when reading offline PCAPs to ignore invalid checksums caused by network interface TCP/UDP checksum offloading:

```bash
zeek -C -r capture.pcap

```

---

### 3. Zui (Zed Engine)

Desktop client for querying structured Zeek datasets using the Zed pipeline language.

**Installation:**
Download the Debian release directly from the official [Brimdata/Zui repository](https://github.com/brimdata/zui):

```bash
sudo dpkg -i zui_*.deb
sudo apt install -f -y

```

---

### 4. NetworkMiner via Mono Runtime (Setup & Workarounds)

Network Forensic Analysis Tool (NFAT) requiring the Mono CLI runtime under Linux.

**Dependencies & File Placement:**

```bash
sudo apt update
sudo apt install mono-devel libmono-system-windows-forms4.0-cil -y

wget https://www.netresec.com/?download=NetworkMiner -O /tmp/NetworkMiner.zip
sudo mkdir -p /opt/networkminer
sudo unzip /tmp/NetworkMiner.zip -d /opt/networkminer/
sudo chmod +x /opt/networkminer/NetworkMiner*/NetworkMiner.exe

```

**The Mono Terminfo 4K Exception Fix:**
On modern Debian/Kali releases, launching NetworkMiner can trigger a fatal crash:

```text
[ERROR] FATAL UNHANDLED EXCEPTION: System.TypeInitializationException:
The type initializer for 'System.Windows.Forms.XplatUI' threw an exception.
---> System.Exception: File must be smaller than 4K
at System.TermInfoReader..ctor ...

```

This is caused by the system `xterm-256color` definition exceeding Mono's hardcoded 4096-byte limit.

**Primary Workaround (Decoupled Process - Recommended):**
Bypass `ConsoleDriver` initialization by detaching the process from the terminal:

```bash
nohup mono /opt/networkminer/NetworkMiner*/NetworkMiner.exe > /dev/null 2>&1 &

```

**Alternative Workaround (Minimal Terminfo Profile):**

```bash
mkdir -p ~/.terminfo
cat << 'EOF' > /tmp/xterm.ti
xterm|minimal xterm entry for mono,
    am,
    lines#24,
    cols#80,
    clear=\E[H\E[2J,
    cub1=^H,
    cud1=^J,
    cuf1=\E[C,
    cuu1=\E[A,
    home=\E[H,
EOF
tic -o ~/.terminfo /tmp/xterm.ti
TERMINFO=~/.terminfo TERM=xterm mono /opt/networkminer/NetworkMiner*/NetworkMiner.exe

```

---

## 💻 Tool-Specific Execution Playbooks

Rather than substituting one tool for another, each engine addresses a distinct investigative scale.

### Playbook A: Rapid Baseline Generation with Zeek

Best used upon receiving an unclassified capture to isolate local endpoints and external IP destinations without packet-by-packet inspection.

```bash
# 1. Parse the PCAP into transaction logs
zeek -C -r sample.pcap

# 2. Extract outbound sessions originating from a local subnet
zeek-cut id.orig_h id.resp_h id.resp_p proto < conn.log | grep "^<LOCAL_SUBNET_PREFIX>" | head -n 30

# 3. List authenticated users and services
zeek-cut client service success < kerberos.log | sort -u

```

---

### Playbook B: Headless Command-Line Triage with Tshark

Best used when scripting artifact extraction or querying specific protocols from large PCAPs without launching a graphical interface.

```bash
# Extract distinct source hardware MAC addresses
tshark -r sample.pcap -Y "ip.src == <VICTIM_IP>" -T fields -e eth.src | sort -u

# Extract outbound HTTP URI paths and request methods
tshark -r sample.pcap -Y "ip.src == <VICTIM_IP> and http.request" -T fields -e ip.dst -e http.request.method -e http.request.uri | sort -u

# Extract TLS SNI values during Client Hello handshakes
tshark -r sample.pcap -Y "tls.handshake.type == 1" -T fields -e ip.dst -e tls.handshake.extensions_server_name | sort -u

```

---

### Playbook C: Artifact & Host Profiling with NetworkMiner

Best used for immediate visual reconstruction of hosts, reassembling transmitted files, and carving cleartext certificates.

1. Launch the application:
```bash
nohup mono /opt/networkminer/NetworkMiner*/NetworkMiner.exe > /dev/null 2>&1 &

```


2. Load the capture file via **File -> Open**.
3. **Hosts Tab:** Filter by local subnet IP prefix. Inspect operating system detection strings, NetBIOS computer names, and packet volume counters.
4. **Files Tab:** Sort carved files by size or timestamp to inspect downloaded executables, scripts (`.ps1`, `.bat`, `.vbs`), or staging archives.
5. **Credentials Tab:** Review extracted authentication tokens and domain usernames observed in SMB or HTTP sessions.

---

### Playbook D: Triaging Companion IDS Alerts

Pre-generated Suricata logs provide rapid baseline classification to compare against deep packet analysis.

```bash
# Extract and inspect alerts (standard archive password: 'infected')
unzip *-alerts.zip
cat *.txt | grep -E "ET MALWARE|ET TROJAN|ET CURRENT_EVENTS|ETPRO" | sort -u

```