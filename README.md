# osint-toolkit

A standalone Flask OSINT investigation workspace with explainable custom modules:

- username checker with custom async HTTP checks over 60+ services in `platforms.yaml`
- confidence scoring, categories, manual-review states, and evidence objects
- case workspace with local JSON storage in `data/cases.json`
- entity graph linking usernames, profiles, domains, IPs, ports, files, and metadata
- domain recon with WHOIS, DNS, SPF/DMARC, HTTP headers, TLS certificate info, and basic common-port scan
- web security checks for authorized public/staging targets: security headers, cookies, CORS, form heuristics, reflected XSS and JavaScript URL canaries
- metadata extraction for JPEG/PNG/TIFF and DOCX files with privacy risk scoring
- JSON and Markdown export
- REST API endpoints for username checks, domain recon, cases, and watch rules
- CLI entry point for terminal usage
- tests that mock HTTP responses instead of touching real platforms

This is intentionally not a wrapper around Maigret or Sherlock. The default
engine is small Python code that is easy to read, test, and explain in an
interview.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run Flask

```bash
flask --app app run --debug
```

Open `http://127.0.0.1:5000`.

## API

```bash
curl -X POST http://127.0.0.1:5000/api/check/username \
  -H "Content-Type: application/json" \
  -d '{"username":"john"}'

curl -X POST http://127.0.0.1:5000/api/recon/domain \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","include_ports":true}'

curl -X POST http://127.0.0.1:5000/api/web-security \
  -H "Content-Type: application/json" \
  -d '{"url":"https://staging.example.com/search","params":["q","redirect"]}'

curl http://127.0.0.1:5000/api/cases
curl http://127.0.0.1:5000/api/watch
```

## Run CLI

```bash
python osint_cli.py --username john --domain example.com --format markdown
python osint_cli.py --metadata sample.jpg
```

## Tests

```bash
pytest
```

## Notes

Read `DISCLAIMER.md` before use. Keep scans focused, slow, and authorized.
Local investigation history is stored under `data/` and ignored by git.
Local and private targets such as `127.0.0.1`, `localhost`, `10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`, `::1`, and `.local` names are blocked by
the target guard. Use a public staging domain that you own or are explicitly
authorized to test.
