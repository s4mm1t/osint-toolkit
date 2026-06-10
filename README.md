# osint-mini-toolkit

A standalone Flask application for small, explainable OSINT workflows:

- username checker with custom async HTTP checks over `platforms.yaml`
- domain recon with WHOIS, DNS, and a basic common-port scan
- metadata extraction for JPEG/PNG/TIFF and DOCX files
- JSON and Markdown report export
- CLI entry point for quick terminal usage
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

