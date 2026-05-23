# Militus Cyber — Proprietary SIEM Rules

**165 Snort/Suricata IDS rules** from Militus Cyber (milituscyber.com).

---

## Rules Breakdown

### 1. militus-brointel.rules — Zeek/Bro Threat Intelligence (46 rules)

Integrates with Zeek (formerly Bro) IDS for network-level threat detection using intel feeds.

| Category | Rules | Description |
|----------|-------|-------------|
| DNS Intel | 10 | Suspicious source/destination IPs in DNS queries |
| HTTP Intel | 10 | Suspicious IPs in HTTP requests |
| SSL Intel | 10 | Suspicious IPs in SSL/TLS connections |
| SMTP Intel | 8 | Suspicious email traffic |
| SSH Intel | 4 | Suspicious SSH connections |
| FTP Intel | 4 | Suspicious FTP activity |

**Key SIDs:** 3000014-3000041
**Classtype:** `suspicious-traffic`

### 2. militus-correlated.rules — Attack Chain Correlation (16 rules)

Multi-event correlation rules that chain individual alerts into attack patterns.

| Category | Rules | Description |
|----------|-------|-------------|
| Web Attacks | 6 | Chained web exploitation attempts |
| Intrusion | 2 | Multi-stage intrusion detection |
| Privilege Escalation | 3 | Post-compromise behavior |
| Data Exfiltration | 1 | Suspicious outbound data transfers |
| General Correlation | 4 | Cross-protocol attack chains |

**Key SIDs:** 3000001-3000013
**Classtype:** `correlated-attack`, `correlated-web-attack`, `correlated-intrusion`

### 3. militus-nist.rules — NIST 800-53 Compliance Mapping (32 rules)

Maps network activity to NIST 800-53 security controls for compliance auditing.

| Category | Rules | Description |
|----------|-------|-------------|
| Reconnaissance | 20 | NIST-mapped recon detection |
| Impact Analysis | 9 | Mission impact assessment |
| Coin Mining | 4 | Cryptocurrency mining detection |
| TOR Traffic | 3 | Anonymized traffic detection |
| DOS Detection | 4 | Denial of service detection |
| Brute Force | 2 | Authentication brute-force |

**Key SIDs:** 3000050-3000090
**Classtype:** `nist-recon`, `nist-impact`

### 4. militus-insight-correlated.rules — Insight Correlation (27 rules)

Advanced multi-indicator correlation for high-fidelity threat detection.

**Key SIDs:** 3000100-3000126
**Classtype:** `suspicious-traffic`, `attempted-recon`, `attempted-dos`

### 5. militus-xbit.rules — Cross-Event Flagging (20 rules)

Uses Snort's `xbits` feature for cross-session, cross-protocol threat flagging.

**Key SIDs:** 3000042-3000062
**Classtype:** `suspicious-traffic`

### 6. militus-policy.rules — Security Policy (3 rules)

Organizational security policy enforcement rules.

### 7. militus-test.rules — IDS Validation (21 rules)

Test rules for validating IDS deployment and rule processing.

### 8. community-rules/ — Snort Community Ruleset

Standard Snort community rules including:
- `community.rules` — Community threat signatures
- `snort.conf` — Snort configuration
- `sid-msg.map` — SID to message mapping
- `VRT-License.txt` — Sourcefire VRT license

---

## Rule Format

All rules are written in **Snort/Suricata format**:

```
alert <protocol> <src_ip> <src_port> -> <dst_ip> <dst_port> \
  (msg:"[MILITUS CATEGORY] Description"; \
   program:<bro_module>; \
   bro-intel:<direction>; \
   classtype:<classification>; \
   xbits: set,<tag>,<ttl>; \
   threshold: type limit, track <target>, count <n>, seconds <s>; \
   normalize; \
   reference: milituscyber.com; \
   sid:<id>; \
   pri:<priority>; \
   rev:<revision>;)
```

### Key Directives

| Directive | Purpose |
|-----------|---------|
| `bro-intel` | Zeek/Bro intelligence feed direction (`by_src`, `by_dst`) |
| `xbits` | Cross-session flagging with TTL (e.g., `attacker_suspicious,86000`) |
| `threshold` | Rate limiting to prevent alert fatigue |
| `normalize` | Normalizes traffic for consistent matching |
| `classtype` | Attack classification for priority assignment |
| `reference` | Documentation reference (`milituscyber.com`) |

---

## Usage

### With Snort

```bash
# Include rules in snort.conf
echo 'include $RULE_PATH/militus-brointel.rules' >> /etc/snort/snort.conf
echo 'include $RULE_PATH/militus-correlated.rules' >> /etc/snort/snort.conf
snort -c /etc/snort/snort.conf -i eth0
```

### With Suricata

```bash
# Copy to Suricata rules directory
cp militus-*.rules /etc/suricata/rules/
suricata-update
systemctl restart suricata
```

### With Graylog + Zeek

```bash
# Load into Zeek's intel framework
cp militus-brointel.rules /opt/zeek/share/zeek/policy/intel/
zeekctl deploy
```

---

## Repository Structure

```
SIEM-rules/
├── README.md
├── militus-brointel.rules          # 46 rules - Zeek/Bro intel
├── militus-correlated.rules        # 16 rules - attack chain correlation
├── militus-insight-correlated.rules # 27 rules - insight correlation
├── militus-nist.rules              # 32 rules - NIST 800-53 mapping
├── militus-policy.rules            # 3 rules - security policy
├── militus-test.rules              # 21 rules - IDS testing
├── militus-xbit.rules              # 20 rules - cross-event flagging
├── community-rules/
│   └── community-rules/
│       ├── community.rules         # Snort community signatures
│       ├── snort.conf              # Snort configuration
│       ├── sid-msg.map             # SID to message mappings
│       ├── AUTHORS
│       ├── LICENSE
│       └── VRT-License.txt
└── community-rules-1/
    └── community-rules/
        ├── community.rules
        ├── militus-test.rules
        ├── snort.conf
        ├── sid-msg.map
        ├── AUTHORS
        ├── LICENSE
        └── VRT-License.txt
```

## Stats

| Metric | Value |
|--------|-------|
| Total Snort/Suricata alerts | 165 |
| Unique SIDs | 95 |
| Class types | 17 |
| Proprietary rules (Militus) | 145 |
| Community rules | 20 |
| Total lines | 554 |

### Class Type Distribution

| Class Type | Count |
|-----------|-------|
| `suspicious-traffic` | 77 |
| `nist-impact` | 41 |
| `app-vulnerability` | 21 |
| `nist-recon` | 20 |
| `correlated-attack` | 9 |
| `correlated-web-attack` | 6 |
| `traffic-normal` | 5 |
| `traffic-coin-mining` | 4 |
| `attempted-recon` | 4 |
| `attempted-dos` | 4 |
| `traffic-tor` | 3 |
| `correlated-privilege-escalation` | 3 |
| `traffic-dos` | 2 |
| `correlated-intrusion` | 2 |
| `brute-force` | 2 |
| `trojan-activity` | 1 |
| `correlated-data-exfiltration` | 1 |

---

