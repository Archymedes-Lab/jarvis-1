"""What the research refresh searches for, and where.

Data only: the publishers searched and the topic queries, grouped so a refresh
can run one topic at a time. research.py drives it.
"""

# Publishers that do primary host-based threat research and publish concrete
# artefacts rather than commentary. Anything outside this list is not searched:
# the goal is indicators for a specific machine, not security news.
SOURCES = [
    "elastic.co", "research.intezer.com", "unit42.paloaltonetworks.com",
    "securelist.com", "welivesecurity.com", "blog.talosintelligence.com",
    "sysdig.com", "thedfirreport.com", "redcanary.com", "huntress.com",
    "volexity.com", "sentinelone.com", "cloud.google.com", "aquasec.com",
    "securitylabs.datadoghq.com", "microsoft.com", "crowdstrike.com",
    "trendmicro.com", "research.checkpoint.com", "blog.sekoia.io",
    "zscaler.com", "proofpoint.com", "cybereason.com", "wiz.io",
    "objective-see.org", "jpcert.or.jp", "cisa.gov", "attack.mitre.org",
    "malwarebytes.com", "sophos.com", "group-ib.com", "socradar.io",
    "bitdefender.com", "fortinet.com", "splunk.com", "binarly.io",
    "eclypsium.com", "orca.security", "snyk.io", "socket.dev",
    "securityintelligence.com", "research.nccgroup.com", "labs.withsecure.com",
    "rapid7.com", "reversinglabs.com", "lab52.io", "team-cymru.com",
    "blog.qualys.com", "akamai.com", "varonis.com", "esentire.com",
    "expel.com", "dragos.com", "sigmahq.io", "abuse.ch", "netskope.com",
    "arcticwolf.com", "kroll.com", "secureworks.com", "hunt.io",
]

# The corpus is grouped so a refresh can run one topic at a time and keep the
# per-run cost bounded. Queries are phrased as descriptions of the document
# wanted, which is what Exa's neural index is built to match — not keywords.
CORPUS = {
    "linux-malware": [
        "technical analysis of new Linux malware with indicators of compromise and persistence details",
        "Linux rootkit using eBPF or loadable kernel module to hide processes, with detection guidance",
        "Linux persistence via systemd unit, cron, or shared library preloading observed in the wild",
        "malware abusing memfd_create or fileless in-memory execution on Linux",
    ],
    "windows-malware": [
        "Windows malware technical analysis with registry persistence keys and file paths",
        "Windows scheduled task and service persistence used by a named threat actor",
        "bring your own vulnerable driver attack technical breakdown with driver names",
        "NTFS alternate data stream and COM hijacking persistence observed in intrusions",
    ],
    "spyware": [
        "commercial spyware or stalkerware technical analysis with host artifacts",
        "infostealer malware analysis listing browser credential theft file paths",
        "keylogger and screen capture malware technical indicators of compromise",
        "remote access trojan analysis with command and control infrastructure details",
    ],
    "infiltration": [
        "initial access technique analysis phishing to code execution with artifacts",
        "supply chain compromise of npm or PyPI package with malicious payload analysis",
        "living off the land binary abuse for execution and defense evasion",
        "credential theft and lateral movement techniques observed in real intrusions",
    ],
    "forensics": [
        "digital forensics incident response artifacts for detecting host compromise",
        "Windows event log and prefetch forensic artifacts proving execution",
        "Linux forensic triage of a compromised host what artifacts to collect",
        "anti-forensics and log tampering techniques used by intruders",
    ],
    "offensive": [
        "penetration testing tradecraft and command and control framework detection",
        "red team persistence tradecraft and the artifacts it leaves behind",
        "post exploitation tooling analysis with host-based detection opportunities",
    ],
    "wsl-and-dev": [
        "attacks abusing Windows Subsystem for Linux for evasion and persistence",
        "malware targeting developer workstations source code and CI credentials",
        "malicious VSCode extension or IDE plugin analysis with indicators",
        "container escape and Docker socket abuse technical analysis",
    ],
    # The agent surface is new enough that the research describing it is not
    # yet indexed under the malware or supply-chain phrasing above: the primary
    # sources call it tool poisoning, auto-execution or skill distribution.
    "agent-toolchain": [
        "MCP server tool poisoning and IDE auto-execution vulnerability analysis",
        "malicious AI coding agent skill or plugin marketplace campaign with indicators",
        "prompt injection through repository files targeting AI coding agents",
        "backdoored IDE extension supply chain incident with detection guidance",
    ],
    "exploited": [
        "actively exploited vulnerability with observed in the wild exploitation artifacts",
        "CISA known exploited vulnerability technical analysis and detection",
    ],
    "ransomware": [
        "ransomware technical analysis with encryption routine and host artifacts",
        "ransomware affiliate intrusion timeline from initial access to deployment",
        "data extortion group tradecraft and staging tooling analysis",
    ],
    "apt-tradecraft": [
        "nation state threat actor campaign technical analysis with host indicators",
        "espionage implant technical breakdown with persistence and C2 details",
        "threat actor tooling overlap and infrastructure analysis report",
    ],
    "c2-frameworks": [
        "command and control framework beacon analysis and host-based detection",
        "Cobalt Strike Sliver or Mythic implant artifacts and detection guidance",
        "malleable C2 profile and traffic detection engineering analysis",
    ],
    "credential-theft": [
        "credential dumping technique analysis with artifacts and detection",
        "browser cookie and session token theft malware technical analysis",
        "cloud credential and API token theft from developer machines",
        "SSH key and CI secret theft technique analysis",
    ],
    "cloud-container": [
        "container escape and Kubernetes attack technical analysis with artifacts",
        "cloud instance metadata service abuse and credential theft analysis",
        "malicious container image and registry supply chain analysis",
    ],
    "firmware-hardware": [
        "UEFI bootkit or firmware implant technical analysis with detection",
        "malicious signed driver and rootkit loading technique analysis",
        "hardware implant and peripheral attack technical research",
    ],
    "browser-attacks": [
        "malicious browser extension technical analysis with permissions and indicators",
        "browser exploitation and drive-by compromise technical breakdown",
        "clipboard hijacking and browser injection malware analysis",
    ],
    "detection-engineering": [
        "detection engineering rules Sigma or YARA for recent malware family",
        "hunting queries and behavioural detection logic for persistence techniques",
        "EDR telemetry analysis and detection opportunities for evasive malware",
    ],
    "mercenary-spyware": [
        "mercenary spyware forensic analysis with indicators of compromise and infrastructure",
        "Pegasus NSO Group forensic traces process names and network indicators",
        "Candiru DevilsTongue Windows spyware technical analysis with artifacts",
        "FinFisher FinSpy implant technical analysis persistence and C2",
        "Predator Intellexa spyware infrastructure domains and addresses",
        "commercial surveillance vendor implant technical breakdown host artifacts",
        "zero-click exploit chain forensic artifacts left on the device",
        "state sponsored surveillance implant network infrastructure attribution",
        "spyware validator server and anonymised infrastructure IP analysis",
        "forensic methodology for detecting targeted surveillance on a workstation",
    ],
    "backdoors": [
        "SSH backdoor authorized_keys and sshd configuration tampering analysis",
        "web shell and server backdoor technical analysis with detection",
        "reverse shell persistence in shell profile cron or systemd analysis",
        "OpenSSH and PAM backdoor implant technical breakdown",
        "setuid binary and sudoers backdoor privilege persistence analysis",
        "hidden local account and rogue administrator creation detection",
        "backdoored package or dependency with malicious postinstall analysis",
        "firmware and bootloader backdoor persistence technical analysis",
    ],
    "wireless": [
        "rogue access point evil twin attack detection and artifacts",
        "wifi deauthentication attack and forced reconnection technique analysis",
        "ARP spoofing and gateway impersonation detection on a workstation",
        "captive portal and DNS hijack man in the middle wireless attack",
    ],
    "memory-forensics": [
        "detecting unbacked executable memory and reflective DLL injection on Windows",
        "userland API hooking detection comparing ntdll in memory against disk",
        "direct and indirect syscall invocation used to bypass EDR hooks",
        "shellcode detection in process memory technical analysis",
        "process hollowing and module stomping detection technique",
        "memory forensics triage of a live Windows host for injected code",
        "detecting manual mapping and module overwriting by implants",
    ],
    "exploit-mitigations": [
        "Windows process mitigation policies CFG ACG CET shadow stack bypass",
        "control flow integrity and shadow stack enforcement on Windows workstations",
        "SMEP SMAP and hardware exploit mitigation verification techniques",
        "kernel exploit primitives and mitigation bypass technical analysis",
    ],
    "input-injection": [
        "malware using SendInput or keybd_event to drive the user interface",
        "detecting synthetic keystroke injection and UI automation abuse",
        "HID emulation BadUSB attack detection and host artifacts",
    ],
    "interception": [
        "TLS interception rogue root certificate installed by malware analysis",
        "malware modifying proxy settings PAC file or WPAD for traffic interception",
        "port forwarding tunnelling and firewall bypass technique analysis",
        "network boundary bypass via portproxy or filtering platform filters",
        "DNS hijacking and hosts file modification by implants",
    ],
    "network-attacks": [
        "lateral movement and network protocol abuse technical analysis",
        "DNS tunnelling and covert channel exfiltration technique analysis",
        "edge device and VPN appliance compromise technical analysis",
    ],
}
