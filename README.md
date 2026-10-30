# PII & Sensitive Data Scanner

A beginner-friendly Python project that scans text files for likely personal information and exposed secrets. It creates a CSV findings register report with masked evidence, severity, counts, a simple risk score, and suggested remediation.

## Requirements
- Python 3.10+
- No third-party packages

## Run
Open a terminal in this folder:

```bash
python scanner.py
```

Windows alternative:

```powershell
py scanner.py
```

The CSV register is `reports/findings.csv`.

## Scan your own authorized test folder

```bash
python scanner.py --input "path/to/folder" --output reports
```

Supported text formats: `.txt`, `.csv`, `.log`, `.json`, `.md`.

## What it detects
- Email addresses
- Phone-number-like strings
- Generic national-ID-like labels (`NID`, `ID`, `CITIZENSHIP`)
- Payment-card-like digit sequences
- Plaintext password fields
- API-key/access-token/secret-key-like fields

## Important limitations
This is a learning prototype. It uses regular expressions, so false positives and missed matches are possible. The ID pattern is generic and does not validate a Nepalese citizenship number. Card detection does not validate the Luhn checksum. It does not certify GDPR, HIPAA, ISO 27001, or any other compliance framework. Use synthetic data or files you are authorized to scan.

## CV bullet (after you have run and understood it)
**PII & Sensitive Data Scanner | Python**
- Built a Python tool to flag likely personal data and exposed secrets in text files, mask evidence, prioritize findings by severity, and export CSV reports with remediation guidance.
