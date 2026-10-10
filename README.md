# TBH-SQLi

<p align="center">
  <a href="https://github.com/TulungagungBlackHat/TBH-SQLi/actions/workflows/ci.yml"><img src="https://github.com/TulungagungBlackHat/TBH-SQLi/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-MIT-red.svg" alt="License">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/payload-safe-green.svg" alt="Safe payloads">
</p>

Error-based SQL injection detector. Sends a benign quote-terminated probe and looks for database error messages leaked in the response.

Part of the [Tulungagung Black Hat](https://github.com/TulungagungBlackHat) toolset.

## What It Checks

- Reflected SQL syntax error messages (MySQL, PostgreSQL, MSSQL, SQLite fingerprints)
- Status code changes caused by the probe
- JSON output for reporting

Payloads are **read-only syntax probes** — no UNION, no stacked queries, no data extraction. An error message is a strong signal; confirm manually and follow the program's rules for PoC.

## Install

```bash
git clone https://github.com/TulungagungBlackHat/TBH-SQLi
cd TBH-SQLi
pip install -r requirements.txt
```

## Usage

```
usage: sqli.py [-h] -u URL [--json JSON]

options:
  -u, --url URL     Target URL with a query parameter
  --json JSON       Save result as JSON
```

```bash
python3 sqli.py -u "https://example.com/item?id=1" --json result.json
```

## Sample Output

```
[*] Testing https://example.com/item?id=1
[!] Potential SQLi: sql syntax error reflected -> confirm manually
[✓] JSON: result.json
```

## Authorized Use Only

Only against scopes you own or are authorized to test. Error-based probing is passive-ish but still active testing — check program rules. See [SECURITY.md](SECURITY.md).

## Related Tools

- [TBH-AllScan](https://github.com/TulungagungBlackHat/TBH-AllScan) — SQLi plus 9 other modules
- [TBH-IDOR](https://github.com/TulungagungBlackHat/TBH-IDOR) — access-control testing companion

## License

[MIT](LICENSE) — Tulungagung Black Hat, East Java, Indonesia. Always Smile :)
