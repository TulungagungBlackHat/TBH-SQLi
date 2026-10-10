#!/usr/bin/env python3
"""TBH-SQLi v3 - Error-based SQL injection detector (authorized testing only)."""
import argparse, json, os, sys, time, urllib.parse

try:
    import requests
except ImportError:
    print("[!] requests required: pip install requests", file=sys.stderr)
    sys.exit(2)

VERSION = "3.0"
REPO = "https://github.com/TulungagungBlackHat/TBH-SQLi"

def banner():
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[91m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-SQLi v3\033[91m - Error-based          \033[91m║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[91m║\n"
            "╚════════════════════════════════════╝\033[0m")

def color(code, text, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text

ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "mysqli", "pdoexception", "unclosed quotation mark",
    "ora-01756", "ora-00933", "postgresql query failed", "pg_query()", "sqlite3.operationalerror",
    "warning: mysql", "valid mysql result", "sqlstate[", "microsoft ole db provider for sql server",
    "incorrect syntax near", "you have an error in your sql syntax",
]
PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1'",
    "1\"",
]

def build_session(args):
    s = requests.Session()
    s.headers["User-Agent"] = f"TBH-SQLi/{VERSION} (+{REPO})"
    if args.cookie:
        s.headers["Cookie"] = args.cookie
    for h in args.header or []:
        name, _, val = h.partition(":")
        if not val:
            raise SystemExit(f"[!] bad -H value: {h!r}")
        s.headers[name.strip()] = val.strip()
    if args.proxy:
        s.proxies = {"http": args.proxy, "https": args.proxy}
    return s

def inject(url, param, value):
    p = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    if param is None:
        param = next(iter(qs), "id")
    qs[param] = [value]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(qs, doseq=True))), param

def target_params(url, requested):
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query, keep_blank_values=True)
    if requested and requested != "all":
        return [requested]
    return list(qs.keys()) or ["id"]

def detect_error(text):
    low = text.lower()
    for sig in ERROR_SIGNATURES:
        if sig in low:
            return sig
    return None

def scan(session, url, args):
    findings = []
    params = target_params(url, args.param)
    try:
        b = session.get(url, timeout=args.timeout, allow_redirects=True)
        baseline = {"status": b.status_code, "length": len(b.text), "error": detect_error(b.text)}
    except requests.RequestException as e:
        return {"error": f"baseline failed: {e}"}

    for param in params:
        for payload in PAYLOADS:
            test_url, _ = inject(url, param, payload)
            try:
                start = time.time()
                r = session.get(test_url, timeout=args.timeout, allow_redirects=True)
                elapsed = time.time() - start
            except requests.RequestException as e:
                findings.append({"param": param, "payload": payload, "error": str(e), "verdict": "error"})
                continue
            sig = detect_error(r.text)
            # baseline already showed this error text -> not a finding
            if sig and sig != baseline.get("error"):
                findings.append({"param": param, "payload": payload, "url": test_url,
                                 "status": r.status_code, "signature": sig,
                                 "elapsed": round(elapsed, 2), "verdict": "error-based"})
                break
            if args.delay:
                time.sleep(args.delay)

    return {"tool": "TBH-SQLi", "version": VERSION, "target": url,
            "baseline": baseline, "findings": findings}

def main():
    parser = argparse.ArgumentParser(description=f"TBH-SQLi v{VERSION} - error-based SQLi detector")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--param", help="parameter name, or 'all' (default: first param)")
    parser.add_argument("--proxy", help="e.g. http://127.0.0.1:8080 (Burp)")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("-H", "--header", action="append", help="extra header, repeatable")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--json", help="save JSON report")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-SQLi {VERSION}")
    args = parser.parse_args()
    print(banner())

    use_color = not args.no_color and not os.environ.get("NO_COLOR")
    print(color("91", "[!] Authorized targets only. Syntax probes only - no data extraction.", use_color))
    print(f"[*] Scanning {args.url} ({len(PAYLOADS)} payloads)")
    try:
        session = build_session(args)
    except SystemExit as e:
        print(e, file=sys.stderr)
        sys.exit(2)

    report = scan(session, args.url, args)
    if "error" in report:
        print(color("91", f"[!] {report['error']}", use_color))
        sys.exit(2)

    vuln = 0
    for f in report["findings"]:
        if f.get("verdict") == "error-based":
            vuln += 1
            print(color("91", f"[!] SQLi on {f['param']}: payload={f['payload']!r} signature={f['signature']!r}", use_color))
        elif f.get("verdict") == "error":
            print(color("90", f"[-] {f['param']}: {f['error']}", use_color))

    if args.json:
        report["summary"] = {"error_based": vuln}
        try:
            with open(args.json, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(color("91", f"[!] cannot write JSON: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    if vuln:
        print(color("91", f"[!] {vuln} parameter(s) leaked DB error text - High, verify & report", use_color))
        sys.exit(1)
    print(color("92", "[✓] No SQL error signatures beyond baseline", use_color))
    sys.exit(0)

if __name__ == "__main__":
    main()
