MALICIOUS_IPS = set([
    "38.121.43.65", "204.79.197.203", "77.91.124.20", "20.22.207.36", "52.159.127.243"
])
SUSPICIOUS_KEYWORDS = [
    "meterpreter", "mimikatz", "r77", "cobalt", "powersploit", "psexec",
    "empire", "suspicious", "dump", "hack", "inject", "keylogger", "remcos"
]
BENIGN_PROCESSES = [
    "explorer.exe", "svchost.exe", "System", "services.exe", "lsass.exe", "winlogon.exe", "csrss.exe"
]
SUSPECT_LOCATIONS = [
    r"\temp\\?", r"\\appdata\\local\\temp", r"\\windows\\temp", r"\\programdata\\", r"\\users\\public\\"
]
