
#!/usr/bin/env python3
"""PII & Sensitive Data Scanner — synthetic-data learning project."""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

RULES = {
    "Email address": (
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
        "LOW",
        "Restrict access and confirm a business need for storing email addresses."
    ),
    "Phone number": (
        re.compile(r"(?<!\w)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)\d{3,4}[\s.-]?\d{3,4}(?!\w)"),
        "MEDIUM",
        "Mask phone numbers in test data and limit access to legitimate users."
    ),
    "National ID-like number": (
        re.compile(r"\b(?:ID|NID|CITIZENSHIP)\s*[:#-]?\s*[A-Z0-9-]{6,18}\b", re.I),
        "HIGH",
        "Verify necessity, restrict access, and use a token or masked value where possible."
    ),
    "Payment-card-like number": (
        re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
        "HIGH",
        "Do not store full card numbers in plain text; use a payment provider/tokenization."
    ),
    "Password field": (
        re.compile(r"""(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s,'";]{4,})"""),
        "CRITICAL",
        "Remove plaintext credentials, rotate the exposed secret, and use a secrets manager."
    ),
    "API-key-like secret": (
        re.compile(r"""(?i)\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*['"]?([A-Za-z0-9_\-./+=]{8,})"""),
        "CRITICAL",
        "Revoke and rotate the exposed secret; store secrets in a secrets manager."
    ),
}

MASKS = {
    "Email address": "[EMAIL REDACTED]",
    "Phone number": "[PHONE REDACTED]",
    "National ID-like number": "[ID REDACTED]",
    "Payment-card-like number": "[CARD REDACTED]",
    "Password field": "[SECRET REDACTED]",
    "API-key-like secret": "[SECRET REDACTED]",
}

WEIGHTS = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 6,
    "CRITICAL": 10
}


@dataclass
class Finding:
    file: str
    line: int
    data_type: str
    severity: str
    masked_evidence: str
    remediation: str


def mask_line(line: str) -> str:
    result = line

    for kind in (
        "Password field",
        "API-key-like secret",
        "National ID-like number",
        "Payment-card-like number",
        "Email address",
        "Phone number"
    ):
        result = RULES[kind][0].sub(MASKS[kind], result)

    return result.strip()[:240]


def scan_file(path: Path, root: Path) -> list[Finding]:
    try:
        raw = path.read_bytes()

        if b"\x00" in raw:
            return []

        content = raw.decode("utf-8", errors="replace")

    except OSError:
        return []

    try:
        relative = str(path.relative_to(root))
    except ValueError:
        relative = path.name

    findings = []

    for line_no, line in enumerate(content.splitlines(), 1):
        for kind, (pattern, severity, remediation) in RULES.items():
            for _ in pattern.finditer(line):
                findings.append(
                    Finding(
                        relative,
                        line_no,
                        kind,
                        severity,
                        mask_line(line),
                        remediation
                    )
                )

    return findings


def score_findings(findings: list[Finding]) -> int:
    return min(100, sum(WEIGHTS[f.severity] for f in findings))


def risk_level(score: int) -> str:
    if score >= 40:
        return "CRITICAL"
    if score >= 20:
        return "HIGH"
    if score >= 8:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NO FINDINGS"


def write_reports(findings: list[Finding], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)

    csv_path = output / "findings.csv"

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(Finding.__dataclass_fields__)
        )

        writer.writeheader()
        writer.writerows(asdict(x) for x in findings)


def main():
    parser = argparse.ArgumentParser(
        description="Scan text files for likely PII and exposed secrets."
    )

    parser.add_argument(
        "--input",
        default="sample_data",
        help="File or folder to scan"
    )

    parser.add_argument(
        "--output",
        default="reports",
        help="Report output folder"
    )

    args = parser.parse_args()

    target = Path(args.input).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()

    if not target.exists():
        parser.error(f"Input does not exist: {target}")

    supported = {".txt", ".csv", ".log", ".json", ".md"}

    candidates = (
        [target]
        if target.is_file()
        else sorted(p for p in target.rglob("*") if p.is_file())
    )

    files = []

    for p in candidates:
        if p.suffix.lower() not in supported or p.is_symlink():
            continue

        if output == p or output in p.parents:
            continue

        files.append(p)

    root = target if target.is_dir() else target.parent

    findings = []
    scanned = []

    for p in files:
        scanned.append(str(p.relative_to(root)))
        findings.extend(scan_file(p, root))

    counts = Counter(f.data_type for f in findings)
    score = score_findings(findings)

    print("\n=== PII & SENSITIVE DATA SCANNER ===")
    print(f"Files scanned : {len(scanned)}\nFindings      : {len(findings)}")
    print(f"Risk score    : {score}/100\nOverall risk  : {risk_level(score)}")

    print("\nFindings by type:")

    for kind, count in sorted(counts.items()):
        print(f"  {kind:<28} {count}")

    if not counts:
        print("  No findings.")

    write_reports(findings, output)

    print(f"\nCSV report : {output / 'findings.csv'}")
    print("\nNote: Findings require human review; this is not a compliance certification.")


if __name__ == "__main__":
    main()
