"""Local ZAP 2.17.0 inventory inspected on 2026-09-13. Not live discovery."""

PASSIVE_RULES = """10003|Vulnerable JS Library (Powered by Retire.js)
10020|Anti-clickjacking Header
90022|Application Error Disclosure
10044|Big Redirect Detected (Potential Sensitive Information Leak)
10015|Re-examine Cache-control Directives
90011|Charset Mismatch
10038|Content Security Policy (CSP) Header Not Set
10055|CSP
10019|Content-Type Header Missing
10010|Cookie No HttpOnly Flag
90033|Loosely Scoped Cookie
10054|Cookie without SameSite Attribute
10011|Cookie Without Secure Flag
10098|Cross-Domain Misconfiguration
10017|Cross-Domain JavaScript Source File Inclusion
10202|Absence of Anti-CSRF Tokens
10033|Directory Browsing
10097|Hash Disclosure
10034|Heartbleed OpenSSL Vulnerability (Indicative)
10009|In Page Banner Information Leak
2|Private IP Disclosure
3|Session ID in URL Rewrite
10023|Information Disclosure - Debug Error Messages
10024|Information Disclosure - Sensitive Information in URL
10025|Information Disclosure - Sensitive Information in HTTP Referrer Header
10027|Information Disclosure - Suspicious Comments
10105|Weak Authentication Method
10041|HTTP to HTTPS Insecure Transition in Form Post
10042|HTTPS to HTTP Insecure Transition in Form Post
90001|Insecure JSF ViewState
90002|Java Serialization Object
10108|Reverse Tabnabbing
10040|Secure Pages Include Mixed Content
10109|Modern Web Application
10062|PII Disclosure
10115|Script Served From Malicious Domain (polyfill)
10050|Retrieved from Cache
10036|HTTP Server Response Header
10035|Strict-Transport-Security Header
90003|Sub Resource Integrity Attribute Missing
10096|Timestamp Disclosure
10030|User Controllable Charset
10029|Cookie Poisoning
10031|User Controllable HTML Element Attribute (Potential XSS)
10043|User Controllable JavaScript Event (XSS)
10028|Off-site Redirect
10057|Username Hash Found
10032|Viewstate
10061|X-AspNet-Version Response Header
10039|X-Backend-Server Header Information Leak
10052|X-ChromeLogger-Data (XCOLD) Header Information Leak
10021|X-Content-Type-Options Header Missing
10056|X-Debug-Token Information Leak
10037|Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)
10116|ZAP is Out of Date
10111|Authentication Request Identified
10112|Session Management Response Identified
10113|Verification Request Identified
90030|WSDL File Detection
50001|Script Passive Scan Rules
50003|Stats Passive Scan Rule"""

ACTIVE_RULES = """40012|Cross Site Scripting (Reflected)
40018|SQL Injection
90020|Remote OS Command Injection
6|Path Traversal"""


def inventory() -> dict:
    from app.scans.levels import SCAN_LEVELS
    rules = []
    for kind, text in (("passive", PASSIVE_RULES), ("active", ACTIVE_RULES)):
        for line in text.splitlines():
            rule_id, name = line.split("|", 1)
            levels = [level.display_name + ("（準備中）" if not level.available else "")
                      for level in SCAN_LEVELS.values()
                      if kind == "passive" or rule_id in level.active_rule_ids]
            rules.append({"id": rule_id, "name": name, "type": kind, "levels": levels})
    return {"version": "2.17.0", "inspected_at": "2026-09-13", "rules": rules}
