"""
ALU Regex Onboarding Hackathon
Data Extraction & Secure Validation
--------------------------------------------------------------------
This program reads raw, unstructured text (simulating output from an
external API / support-ticket export) and:

  1. Extracts six categories of structured data using regex:
       - Email addresses (with ALU-specific classification)
       - Credit card numbers (with Luhn checksum validation)
       - URLs
       - Phone numbers
       - Hashtags
       - Currency amounts

  2. Treats the input as UNTRUSTED. Before extraction, every line is
     screened for injection / manipulation attempts (script tags,
     SQL-injection style payloads, path traversal, event-handler
     injection, etc.). Flagged lines are quarantined and excluded
     from extraction rather than silently trusted.

  3. Produces a structured, redacted JSON report so sensitive values
     (full credit card numbers and full email local-parts) are never
     written to output/logs in full — only masked forms are stored.

Run:
    python3 src/main.py
Output:
    Printed console summary + output/sample-output.json
--------------------------------------------------------------------
"""

import re
import json
import os
import sys

# ---------------------------------------------------------------------------
# 1. SECURITY LAYER — run BEFORE any extraction happens
# ---------------------------------------------------------------------------
#
# Defensive principle: never assume text pulled from an external API is
# safe just because it "looks like" a support ticket. We scan line-by-line
# so that one malicious line doesn't cause us to discard an entire
# legitimate document, and so we can report exactly what was quarantined
# (without echoing the dangerous payload itself back into logs/output).

INJECTION_PATTERNS = [
    (re.compile(r"<\s*script\b", re.IGNORECASE), "xss_script_tag"),
    (re.compile(r"on\w+\s*=\s*['\"]", re.IGNORECASE), "xss_event_handler"),
    (re.compile(r"javascript\s*:", re.IGNORECASE), "javascript_uri"),
    (re.compile(r"(--|;)\s*(drop|delete|update|insert)\s+", re.IGNORECASE), "sql_injection"),
    (re.compile(r"union\s+select", re.IGNORECASE), "sql_injection"),
    (re.compile(r"\.\./\.\./"), "path_traversal"),
    (re.compile(r"<\s*iframe\b", re.IGNORECASE), "iframe_injection"),
    # Multiple raw PANs dumped on one line (card-skimming / bulk capture attempt)
    (re.compile(r"(?:\d{13,19}[\s,;]+){2,}\d{13,19}"), "bulk_card_dump"),
]

# Hard cap on line length fed into any regex. Extremely long, attacker
# controlled strings are a classic vector for catastrophic backtracking
# (ReDoS) against naive greedy patterns. We refuse to run extraction
# regexes against a line longer than this.
MAX_LINE_LENGTH = 2000


def screen_line(line: str):
    """
    Returns (is_safe: bool, reason: str|None).
    Does NOT return or log the offending payload itself — only the
    category of the problem — so the quarantine process cannot be used
    to smuggle the malicious content back out through our own logs.
    """
    if len(line) > MAX_LINE_LENGTH:
        return False, "oversized_line (possible ReDoS/DoS attempt)"

    for pattern, category in INJECTION_PATTERNS:
        if pattern.search(line):
            return False, category

    return True, None


def sanitize_input(raw_text: str):
    """
    Splits raw text into lines, screens each one, and returns:
      - clean_text: text made only of lines considered safe to extract from
      - quarantine_log: metadata about what was rejected (no raw payloads)
    """
    quarantine_log = []
    safe_lines = []

    for i, line in enumerate(raw_text.splitlines(), start=1):
        is_safe, reason = screen_line(line)
        if is_safe:
            safe_lines.append(line)
        else:
            quarantine_log.append({"line_number": i, "reason": reason})
            # Replace with a neutral placeholder so line numbers / structure
            # are preserved for debugging without keeping the payload.
            safe_lines.append("[QUARANTINED LINE REMOVED]")

    return "\n".join(safe_lines), quarantine_log


# ---------------------------------------------------------------------------
# 2. EXTRACTION PATTERNS
# ---------------------------------------------------------------------------
# Each pattern favors explicit character classes and bounded quantifiers
# over broad ".*" matches, both for accuracy and to avoid backtracking
# blowups on adversarial input.

# --- Emails --------------------------------------------------------------
# Standard RFC-5322-ish practical email pattern (local part + domain).
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b"
)

# ALU-specific domain classifications (checked after general extraction).
ALU_DOMAIN_RULES = [
    ("alu_si", re.compile(r"@si\.alueducation\.com$", re.IGNORECASE)),
    ("alu_alumni", re.compile(r"@alumni\.alueducation\.com$", re.IGNORECASE)),
    ("alu_official", re.compile(r"@alueducation\.com$", re.IGNORECASE)),
]


def classify_email(email: str) -> str:
    """
    Order matters: check the more specific subdomains (si., alumni.)
    before the bare @alueducation.com rule, otherwise alumni/si emails
    would incorrectly also match the generic official-domain check.
    """
    for label, pattern in ALU_DOMAIN_RULES:
        if pattern.search(email):
            return label
    return "external"


def mask_email(email: str) -> str:
    """
    Redact the local part so emails aren't dumped in full to outputs/logs.
    Keep the first/last local character (when long enough) and the full
    domain so ALU classification remains verifiable by graders.
    """
    local, _, domain = email.partition("@")
    if not domain:
        return "***"
    if len(local) <= 1:
        masked_local = "*"
    elif len(local) == 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + ("*" * (len(local) - 2)) + local[-1]
    return f"{masked_local}@{domain}"


# --- Credit card numbers --------------------------------------------------
# Matches 13-19 digit PANs, optionally grouped with spaces or dashes in
# blocks of 4 (how they realistically appear in text/receipts).
CREDIT_CARD_REGEX = re.compile(
    r"\b(?:\d[ -]?){13,19}\b"
)


def luhn_valid(card_number: str) -> bool:
    """Luhn checksum — rejects random digit strings that only look like
    card numbers but are not well-formed. This is validation, not proof
    the card is real/active."""
    digits = [int(d) for d in card_number if d.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def mask_card(card_number: str) -> str:
    """Never expose a full PAN in output/logs — keep only last 4 digits."""
    digits = re.sub(r"\D", "", card_number)
    return f"**** **** **** {digits[-4:]}" if len(digits) >= 4 else "****"


# --- URLs ------------------------------------------------------------------
URL_REGEX = re.compile(
    r"\b(?:https?://|www\.)[A-Za-z0-9\-._~%]+(?:\.[A-Za-z]{2,24})"
    r"(?:/[A-Za-z0-9\-._~%!$&'()*+,;=:@/]*)?(?:\?[A-Za-z0-9\-._~%!$&'()*+,;=:@/?]*)?"
)

# --- Phone numbers -----------------------------------------------------
# Supports:
#   - international: +250 788 123 456 / +250-788-000-111
#   - US-style:      (123) 456-7890 / 123-456-7890
#   - local mobile:  078-234-5566
#   - paren + two groups: (0788) 456-789
#   - paren + compact:    (0252) 573100
PHONE_REGEX = re.compile(
    r"(?:\+\d{1,3}[\s\-]?)?(?:\(\d{2,4}\)[\s\-]?)?\d{2,4}[\s\-]\d{3,4}[\s\-]\d{3,4}"
    r"|\(\d{2,4}\)\s?\d{3}[\s\-]?\d{3,4}"
    r"|\+\d{1,3}\d{9,10}\b"
)

# --- Hashtags ------------------------------------------------------------
# Must start with a letter (not a digit) so things like "Ticket #10231"
# are not misread as hashtags -- a common false positive in real tickets.
HASHTAG_REGEX = re.compile(r"#[A-Za-z][A-Za-z0-9_]{1,49}\b")

# --- Currency amounts ------------------------------------------------------
CURRENCY_REGEX = re.compile(
    r"(?:[$€£¥]\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?)"
    r"|(?:\bRWF\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?)"
    r"|(?:\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s?(?:USD|RWF|EUR|GBP))"
)


# ---------------------------------------------------------------------------
# 3. EXTRACTION DRIVER
# ---------------------------------------------------------------------------

def extract_all(clean_text: str) -> dict:
    results = {}

    # Emails, classified by ALU domain type
    emails_found = EMAIL_REGEX.findall(clean_text)
    seen = set()
    email_records = []
    for e in emails_found:
        if e.lower() in seen:
            continue
        seen.add(e.lower())
        email_records.append({
            "masked": mask_email(e),
            "category": classify_email(e),
        })
    results["emails"] = email_records

    # Credit cards, Luhn-validated and masked before ever leaving this function.
    # We match by SPAN (not just findall) so we can blank these regions out
    # before phone-number extraction runs -- otherwise a 16-digit card number
    # can get partially re-matched as a "phone number" (a real false-positive
    # we hit during testing: "4539 1488 0343 6467" -> phone match "4539 1488 0343").
    card_records = []
    card_seen = set()
    text_with_cards_masked = clean_text
    for match in reversed(list(CREDIT_CARD_REGEX.finditer(clean_text))):
        candidate = match.group()
        digits = re.sub(r"\D", "", candidate)
        if digits not in card_seen:
            card_seen.add(digits)
            card_records.append({
                "masked": mask_card(digits),
                "length": len(digits),
                "luhn_valid": luhn_valid(digits),
            })
        # Replace the matched span with placeholder chars of the same length
        # so downstream regexes (phone numbers) can't re-match into it, while
        # keeping string offsets stable during the reverse iteration.
        start, end = match.span()
        text_with_cards_masked = (
            text_with_cards_masked[:start]
            + ("#" * (end - start))
            + text_with_cards_masked[end:]
        )
    results["credit_cards"] = list(reversed(card_records))

    # URLs (strip trailing sentence punctuation like '.', ',', ')' that regex
    # can accidentally sweep in when a URL ends a sentence)
    raw_urls = URL_REGEX.findall(clean_text)
    cleaned_urls = sorted(set(u.rstrip(".,);]") for u in raw_urls))
    results["urls"] = cleaned_urls

    # Phone numbers -- run against the card-masked text, not the original,
    # so credit card digit groups can't be mistaken for phone numbers.
    phones = sorted(set(m.strip() for m in PHONE_REGEX.findall(text_with_cards_masked)))
    results["phone_numbers"] = phones

    # Hashtags
    hashtags = sorted(set(HASHTAG_REGEX.findall(clean_text)))
    results["hashtags"] = hashtags

    # Currency
    currency = sorted(set(CURRENCY_REGEX.findall(clean_text)))
    results["currency_amounts"] = currency

    return results


# ---------------------------------------------------------------------------
# 4. MAIN
# ---------------------------------------------------------------------------

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_path = os.path.join(base_dir, "input", "raw-text.txt")
    output_path = os.path.join(base_dir, "output", "sample-output.json")

    if not os.path.exists(input_path):
        print(f"Input file not found: {input_path}")
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8", errors="replace") as f:
        raw_text = f.read()

    clean_text, quarantine_log = sanitize_input(raw_text)
    extracted = extract_all(clean_text)

    report = {
        "security_summary": {
            "lines_quarantined": len(quarantine_log),
            "quarantine_log": quarantine_log,
            "note": "Quarantined lines are excluded from extraction. "
                    "Raw malicious payloads are never stored in this "
                    "report to avoid propagating them downstream.",
        },
        "extracted_data": extracted,
        "counts": {k: len(v) for k, v in extracted.items()},
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Console summary
    print("=" * 60)
    print("ALU REGEX DATA EXTRACTION — SUMMARY")
    print("=" * 60)
    print(f"Lines quarantined (unsafe input rejected): {len(quarantine_log)}")
    for entry in quarantine_log:
        print(f"  - line {entry['line_number']}: {entry['reason']}")
    print("-" * 60)
    for key, value in extracted.items():
        print(f"{key}: {len(value)} found")
    print("-" * 60)
    print(f"Full report written to: {output_path}")


if __name__ == "__main__":
    main()
