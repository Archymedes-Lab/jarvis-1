"""Built-in answers to the security questions people ask most.

ARGUS-INSTINCT does not need an AI model to be useful. Questions about this
computer are answered from its own data (assistant.py); common questions about
staying safe are answered here from a short, reviewed list. Every entry is
plain language, says what to do next, and never advises weakening protection,
wiping disks or paying anyone. Matching is deliberate and conservative: an
entry answers only when its own words appear, so an unrelated question falls
through to the next step instead of getting a confident wrong answer.

The text is English; the interface language does not change it yet.
"""

import re

# (id, keyword phrases (any one), answer)
ENTRIES = (
    ("phishing", ("phishing", "phish", "fake email", "fake website", "suspicious email", "scam email"),
     "Phishing is a message or website that pretends to be someone you trust, such as your bank, to trick you "
     "into giving away a password or money. Do not click links or open attachments you did not expect. "
     "Instead, type the company's address yourself or use its official app. Real companies do not "
     "ask for your password by email."),
    ("password", ("strong password", "good password", "create a password", "choose a password", "password manager",
                  "password advice", "safe password"),
     "Use a long, different password for every account; a few random words strung together works well. "
     "You cannot remember dozens of them, so use a password manager, which stores them encrypted. "
     "Never reuse your email password anywhere else, because email can reset your other accounts."),
    ("2fa", ("two-factor", "two factor", "2fa", "mfa", "multi-factor", "multi factor", "authenticator",
             "verification code"),
     "Two-factor sign-in asks for a second proof besides your password, such as a code from an "
     "authenticator app. Even if someone steals your password, they cannot get in without it. "
     "Turn it on for email, banking and social media first. An app is safer than text messages."),
    ("ransomware", ("ransomware", "files are encrypted", "pay the ransom", "files locked"),
     "Ransomware locks your files and demands money. Do not pay: payment does not guarantee you get your "
     "files back. Disconnect the computer from the internet, do not turn off your backups, and restore from "
     "a backup that was kept offline. The best protection is regular backups and keeping Windows up to date."),
    ("backup", ("backup", "back up", "back-up"),
     "A backup is a second copy of your important files, kept somewhere else. Follow the 3-2-1 rule: three copies, "
     "on two kinds of storage, with one kept away from the computer, such as an external drive you unplug or "
     "a cloud service. A backup that is always plugged in can be locked by ransomware too."),
    ("updates", ("software update", "windows update", "should i update", "keep updated", "security update", "patch"),
     "Updates fix security holes that attackers already know about. Turn on automatic updates for Windows and "
     "your browser, and restart when asked. Updating is one of the most effective things you can do."),
    ("public-wifi", ("public wifi", "public wi-fi", "coffee shop wifi", "airport wifi", "hotel wifi", "free wifi"),
     "Public Wi-Fi is shared with strangers. Avoid banking or typing passwords on it unless the site uses "
     "https (the padlock) or you use a trusted VPN. Your phone's hotspot is safer. Turn off automatic "
     "connecting to open networks."),
    ("vpn", ("vpn", "virtual private network"),
     "A VPN hides your internet traffic from the network you are on, such as public Wi-Fi, and from your "
     "internet provider. It does not make you immune to viruses or phishing, and the VPN company can see "
     "your traffic instead, so choose a trusted one."),
    ("firewall", ("what is a firewall", "firewall", "inbound rule"),
     "A firewall decides which programs may send and receive data over the network. Windows has one built "
     "in and it should stay on. Do not turn it off to fix a problem; allow the single program you trust instead."),
    ("antivirus", ("do i need antivirus", "need an antivirus", "is windows defender enough", "defender enough",
                   "which antivirus", "best antivirus"),
     "For most people, the Windows Defender that comes with Windows is a solid antivirus, as long as it is on and "
     "updated. ARGUS-INSTINCT does not replace it: ARGUS-INSTINCT watches for unusual things and explains them, "
     "while Defender blocks known viruses. Running two full antivirus programs together can cause problems."),
    ("malware", ("what is malware", "what is a virus", "what are viruses", "what is a trojan", "what is spyware",
                 "what is adware"),
     "Malware is any program made to harm you or spy on you: viruses, trojans that pretend to be useful, "
     "spyware that watches what you do, and ransomware. It usually arrives through a fake download, an email "
     "attachment or a hacked website. Keep Windows updated, only install software from official sources, "
     "and be careful with attachments."),
    ("tech-support-scam", ("tech support scam", "microsoft called", "fake support", "virus alert popup", "pop-up says",
                           "popup says", "call this number", "remote access request"),
     "A real company will not cold-call or pop up a message telling you to call a number because you have a virus. "
     "Close the page, do not call, and never let a stranger connect to your computer or ask you to buy gift "
     "cards. If you already let someone in, disconnect from the internet and change your important passwords "
     "from a different device."),
    ("hacked", ("i got hacked", "i was hacked", "been hacked", "think i'm hacked", "think im hacked", "account hacked",
                "what if i am hacked", "what do i do if i'm hacked", "what do i do if i am hacked"),
     "Stay calm and act in this order: 1) from a different, clean device, change the password of the "
     "affected account, starting with your email; 2) turn on two-factor sign-in; 3) check the account's "
     "recent activity and sign out of all devices; 4) tell your bank if money is involved. Do not wipe the "
     "computer yet; ARGUS-INSTINCT's findings can help show what happened."),
    ("attachments", ("email attachment", "open an attachment", "attachment safe", "zip file from email"),
     "Be wary of attachments you did not expect, even from people you know, because their account may be "
     "hacked. Be extra careful with .exe, .scr, .js, .zip and Office files that ask you to 'enable "
     "macros' or 'enable content'. If in doubt, ask the sender by another route."),
    ("downloads", ("safe download", "download software", "where to download", "is this download safe", "cracked software",
                   "free software"),
     "Download programs only from the official website or the Microsoft Store. Cracked or 'free' copies of paid "
     "software are a very common way malware spreads. Skip bundled 'extras' in installers and check the web "
     "address carefully."),
    ("usb", ("usb drive", "usb stick", "found a usb", "flash drive", "unknown usb"),
     "Do not plug in a USB drive you found or were given by someone you do not know; it can carry malware or "
     "be built to attack your computer. If you must use one, scan it first with Windows Security."),
    ("extensions", ("browser extension", "chrome extension", "browser add-on", "browser plugin"),
     "Browser extensions can read the pages you visit, so each one is trusted with a lot. Keep only the ones "
     "you recognise and use, remove the rest, and install only from the official store."),
    ("keylogger", ("keylogger", "key logger", "someone watching my screen", "spying on me", "stalkerware", "am i being spied"),
     "Spyware and keyloggers record what you type or see. Signs include a webcam light that comes on by itself, "
     "unknown programs that start with Windows, or unusual network use. ARGUS-INSTINCT looks for these. If you "
     "suspect it, change your passwords from a different device and review the findings ARGUS-INSTINCT shows."),
    ("encryption", ("what is encryption", "encrypt my files", "bitlocker", "disk encryption", "device encryption"),
     "Encryption scrambles data so only someone with the key can read it. Turning on BitLocker or Device "
     "Encryption in Windows protects your files if your laptop is lost or stolen. Keep a copy of the "
     "recovery key somewhere safe, not only on the same computer."),
    ("privacy", ("privacy settings", "protect my privacy", "online privacy", "social media privacy", "track me", "tracking"),
     "Review the privacy settings on your accounts, share less personal detail publicly, and check which apps "
     "have access to your camera, microphone and location. In Windows, look in Settings, then Privacy. "
     "Using a different email address for sign-ups also limits tracking."),
    ("camera-mic", ("webcam", "camera light", "microphone access", "who is using my camera"),
     "Windows shows which apps have used your camera or microphone in Settings, then Privacy and security. "
     "Turn access off for apps that do not need it. A cheap sliding cover over the webcam is also a "
     "simple, reliable protection."),
    ("slow", ("computer is slow", "pc is slow", "laptop is slow", "why is my computer slow", "computer running slow"),
     "Slowness has many ordinary causes: too many programs starting with Windows, low disk space, or pending "
     "updates. Malware is only one possible cause. Restart, check Task Manager for what is using the "
     "most, and free up disk space. If ARGUS-INSTINCT shows no findings, an infection is less likely."),
    ("safe-argus", ("is argus-1 safe", "is argus safe", "does argus-1 send", "does argus send", "is my data private",
                    "where does my data go", "does argus-1 collect", "what does argus-1 collect"),
     "ARGUS-INSTINCT works on your computer. What it observes stays here, and it talks to the network only for "
     "things you turn on, such as buying a licence at pay.archymedes.xyz or optional email alerts. It reads and explains; "
     "it does not change your computer without your approval."),
    ("what-argus", ("what is argus-1", "what is argus", "what does argus-1 do", "what does argus do"),
     "ARGUS-INSTINCT watches your computer for things that look wrong, such as programs that start by themselves, "
     "passwords left in plain files, or risky settings, and explains them in plain language. It "
     "tells you what to do next and never changes anything without your approval. It works alongside "
     "Windows' own antivirus, not instead of it."),
    ("score", ("what does the score mean", "what is the score", "security score mean", "what is a good score"),
     "The score is a quick summary of how many open issues ARGUS-INSTINCT sees and how serious they are. "
     "A lower score means more things worth a look; it is not proof that your computer is infected. "
     "Open 'What I found' to see what is lowering it and which fix helps most."),
)

_WORD = re.compile(r"[a-z0-9']+")


def _norm(text):
    return " ".join(_WORD.findall((text or "").lower().replace("’", "'")))


def lookup(question):
    """-> the entry's answer text, or "" when nothing matches clearly."""
    q = _norm(question)
    if not q:
        return ""
    best, best_len = "", 0
    for _id, phrases, answer in ENTRIES:
        for phrase in phrases:
            p = _norm(phrase)
            # Whole-word match, so "vpn" does not match inside another word.
            if re.search(r"(?<![a-z0-9])" + re.escape(p) + r"(?![a-z0-9])", q) and len(p) > best_len:
                best, best_len = answer, len(p)
    return best


def topics():
    """Short topic names for suggestions."""
    return [e[0] for e in ENTRIES]
