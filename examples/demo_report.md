# Tracehound report - demo_breach.pcap

- **Capture window:** 2025-10-09 08:53:21 UTC to 2025-10-09 09:10:18 UTC (1016.5s, 5107 packets)
- **Internal hosts:** 192.168.1.1, 192.168.1.10, 192.168.1.15, 192.168.1.20, 192.168.1.31, 192.168.1.42
- **Findings:** 2 critical, 4 high, 1 medium
- **Likely first compromised host:** 192.168.1.20

## Attack timeline

- `2025-10-09 08:56:40 UTC` - **CRITICAL** [Initial Access / Execution] Suspicious download by 192.168.1.20 (F1, T1105 Ingress Tool Transfer) [frames 262]
- `2025-10-09 08:57:40 UTC` - **HIGH** [Credential Access] Credentials sent unencrypted over HTTP (F2, T1552 Unsecured Credentials) [frames 416]
- `2025-10-09 08:58:20 UTC` - **HIGH** [Command and Control] 192.168.1.20 looked up 12 random-looking domain(s) (F3, T1568.002 Domain Generation Algorithms) [frames 417, 421, 425, 431, 437, 441]
- `2025-10-09 08:58:20 UTC` - **MEDIUM** [Command and Control] 192.168.1.20 got 12 failed DNS lookups (F4, T1568.002 Domain Generation Algorithms) [frames 418, 422, 426, 432, 436, 440]
- `2025-10-09 08:58:27 UTC` - 192.168.1.20 resolved q7x9k2m4vb8z.top to 203.0.113.50 [frame 442]
- `2025-10-09 08:58:41 UTC` - **HIGH** [Command and Control] Regular beaconing from 192.168.1.20 to 203.0.113.50 (q7x9k2m4vb8z.top) (F5, T1071 Application Layer Protocol) [frames 443, 453, 463, 473, 483, 515]
- `2025-10-09 09:09:10 UTC` - **HIGH** [Discovery / Lateral Movement] Network sweep on port 445 by 192.168.1.20 (F6, T1046 Network Service Discovery) [frames 493, 498, 502, 505, 510, 514]
- `2025-10-09 09:10:00 UTC` - **CRITICAL** [Exfiltration] Large upload from 192.168.1.20 to 203.0.113.50 (q7x9k2m4vb8z.top) (F7, T1041 Exfiltration Over C2 Channel) [frames 747, 1573, 2399, 3225, 4051, 4877]

## Findings

### F1 - Suspicious download by 192.168.1.20
**Severity:** CRITICAL | **Stage:** Initial Access / Execution | **MITRE ATT&CK:** T1105 Ingress Tool Transfer

192.168.1.20 requested http://198.51.100.7/docs/invoice_8841.exe from 198.51.100.7: executable/script file (exe); scripted client user-agent 'Microsoft BITS/7.8'; request to a raw IP address instead of a domain.

Seen 2025-10-09 08:56:40 UTC to 2025-10-09 08:56:40 UTC. Evidence:

- frame 262: `TCP 192.168.1.20:49169 -> 198.51.100.7:80 len=131 flags=PA | HTTP GET 198.51.100.7/docs/invoice_8841.exe UA='Microsoft BITS/7.8'`

### F2 - Credentials sent unencrypted over HTTP
**Severity:** HIGH | **Stage:** Credential Access | **MITRE ATT&CK:** T1552 Unsecured Credentials

192.168.1.20 sent login data (password field in request) in cleartext to 192.168.1.10 (intranet.corp.local) port 80. Anyone on the network path could read it.

Seen 2025-10-09 08:57:40 UTC to 2025-10-09 08:57:40 UTC. Evidence:

- frame 416: `TCP 192.168.1.20:49170 -> 192.168.1.10 (intranet.corp.local):80 len=221 flags=PA | HTTP POST intranet.corp.local/login UA='Mozilla/5.0'; CLEARTEXT HTTP: password field in request`

### F3 - 192.168.1.20 looked up 12 random-looking domain(s)
**Severity:** HIGH | **Stage:** Command and Control | **MITRE ATT&CK:** T1568.002 Domain Generation Algorithms

192.168.1.20 queried high-randomness names such as 3efr4edt2sywb3.top, 3xtplpft75v2se.top, 60kvj50ce9uvw5.top, 9ri19r0wyojflj.top. Malware often generates names like these to find its command server.

Seen 2025-10-09 08:58:20 UTC to 2025-10-09 08:58:27 UTC. Evidence:

- frame 417: `UDP 192.168.1.20:49171 -> 192.168.1.1:53 len=64 | DNS query dzdoc9is0j8ht9.top`
- frame 421: `UDP 192.168.1.20:49173 -> 192.168.1.1:53 len=64 | DNS query 3xtplpft75v2se.top`
- frame 425: `UDP 192.168.1.20:49175 -> 192.168.1.1:53 len=64 | DNS query 3efr4edt2sywb3.top`
- frame 431: `UDP 192.168.1.20:49178 -> 192.168.1.1:53 len=64 | DNS query oa5lqsaj08xui6.top`
- frame 437: `UDP 192.168.1.20:49181 -> 192.168.1.1:53 len=64 | DNS query qwx4hh5344tfjg.top`
- frame 441: `UDP 192.168.1.20:49183 -> 192.168.1.1:53 len=62 | DNS query q7x9k2m4vb8z.top`

### F4 - 192.168.1.20 got 12 failed DNS lookups
**Severity:** MEDIUM | **Stage:** Command and Control | **MITRE ATT&CK:** T1568.002 Domain Generation Algorithms

192.168.1.20 asked for 12 domains that do not exist. Malware cycling through generated domains until one answers produces exactly this pattern.

Seen 2025-10-09 08:58:20 UTC to 2025-10-09 08:58:25 UTC. Evidence:

- frame 418: `UDP 192.168.1.1:53 -> 192.168.1.20:49171 len=64 | DNS response dzdoc9is0j8ht9.top NXDOMAIN`
- frame 422: `UDP 192.168.1.1:53 -> 192.168.1.20:49173 len=64 | DNS response 3xtplpft75v2se.top NXDOMAIN`
- frame 426: `UDP 192.168.1.1:53 -> 192.168.1.20:49175 len=64 | DNS response 3efr4edt2sywb3.top NXDOMAIN`
- frame 432: `UDP 192.168.1.1:53 -> 192.168.1.20:49178 len=64 | DNS response oa5lqsaj08xui6.top NXDOMAIN`
- frame 436: `UDP 192.168.1.1:53 -> 192.168.1.20:49180 len=64 | DNS response khvdgaj8gxbeny.top NXDOMAIN`
- frame 440: `UDP 192.168.1.1:53 -> 192.168.1.20:49182 len=64 | DNS response vq4k7bn7xj8b7t.top NXDOMAIN`

### F5 - Regular beaconing from 192.168.1.20 to 203.0.113.50 (q7x9k2m4vb8z.top)
**Severity:** HIGH | **Stage:** Command and Control | **MITRE ATT&CK:** T1071 Application Layer Protocol

192.168.1.20 contacted 203.0.113.50 (q7x9k2m4vb8z.top) on port 443 11 times, about every 60s (jitter 2%). Machine-regular check-ins like this are typical of malware calling its command server.

Seen 2025-10-09 08:58:41 UTC to 2025-10-09 09:10:00 UTC. Evidence:

- frame 443: `TCP 192.168.1.20:49184 -> 203.0.113.50 (q7x9k2m4vb8z.top):443 len=40 flags=S`
- frame 453: `TCP 192.168.1.20:49186 -> 203.0.113.50 (q7x9k2m4vb8z.top):443 len=40 flags=S`
- frame 463: `TCP 192.168.1.20:49188 -> 203.0.113.50 (q7x9k2m4vb8z.top):443 len=40 flags=S`
- frame 473: `TCP 192.168.1.20:49190 -> 203.0.113.50 (q7x9k2m4vb8z.top):443 len=40 flags=S`
- frame 483: `TCP 192.168.1.20:49192 -> 203.0.113.50 (q7x9k2m4vb8z.top):443 len=40 flags=S`
- frame 515: `TCP 192.168.1.20:49214 -> 203.0.113.50 (q7x9k2m4vb8z.top):443 len=40 flags=S`

### F6 - Network sweep on port 445 by 192.168.1.20
**Severity:** HIGH | **Stage:** Discovery / Lateral Movement | **MITRE ATT&CK:** T1046 Network Service Discovery

192.168.1.20 tried port 445 on 20 different hosts in 2s. From an internal machine this often means an attacker or worm is looking for the next target.

Seen 2025-10-09 09:09:10 UTC to 2025-10-09 09:09:11 UTC. Evidence:

- frame 493: `TCP 192.168.1.20:49194 -> 192.168.1.30:445 len=40 flags=S`
- frame 498: `TCP 192.168.1.20:49198 -> 192.168.1.34:445 len=40 flags=S`
- frame 502: `TCP 192.168.1.20:49202 -> 192.168.1.38:445 len=40 flags=S`
- frame 505: `TCP 192.168.1.20:49205 -> 192.168.1.41:445 len=40 flags=S`
- frame 510: `TCP 192.168.1.20:49209 -> 192.168.1.45:445 len=40 flags=S`
- frame 514: `TCP 192.168.1.20:49213 -> 192.168.1.49:445 len=40 flags=S`

### F7 - Large upload from 192.168.1.20 to 203.0.113.50 (q7x9k2m4vb8z.top)
**Severity:** CRITICAL | **Stage:** Exfiltration | **MITRE ATT&CK:** T1041 Exfiltration Over C2 Channel

192.168.1.20 sent 6.3 MB to 203.0.113.50 (q7x9k2m4vb8z.top) but received only 0.01 MB back. Uploads this lopsided to an outside server can mean stolen data.

Seen 2025-10-09 09:10:00 UTC to 2025-10-09 09:10:17 UTC. Evidence:

- frame 747: `TCP 192.168.1.20:49214 -> 203.0.113.50 (q7x9k2m4vb8z.top):443 len=1440 flags=PA`
- frame 1573: `TCP 192.168.1.20:49214 -> 203.0.113.50 (q7x9k2m4vb8z.top):443 len=1440 flags=PA`
- frame 2399: `TCP 192.168.1.20:49214 -> 203.0.113.50 (q7x9k2m4vb8z.top):443 len=1440 flags=PA`
- frame 3225: `TCP 192.168.1.20:49214 -> 203.0.113.50 (q7x9k2m4vb8z.top):443 len=1440 flags=PA`
- frame 4051: `TCP 192.168.1.20:49214 -> 203.0.113.50 (q7x9k2m4vb8z.top):443 len=1440 flags=PA`
- frame 4877: `TCP 192.168.1.20:49214 -> 203.0.113.50 (q7x9k2m4vb8z.top):443 len=1440 flags=PA`

---
Verify any frame in Wireshark with the display filter `frame.number == N`.