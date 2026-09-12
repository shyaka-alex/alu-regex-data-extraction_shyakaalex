# ALU Regex Onboarding Hackathon — Data Extraction & Secure Validation

## Overview

This project simulates a small piece of a production system: raw, unstructured
text comes in from an external source (here, a fake "support ticket export"),
and the program must safely extract structured data from it using regex,
without blindly trusting the input.

It extracts **six** data types (two more than the minimum required):

| Data type          | Notes                                                        |
|---------------------|---------------------------------------------------------------|
| Email addresses      | Also classified into ALU official / alumni / SI / external   |
| Credit card numbers   | Luhn-checksum validated, masked before output                |
| URLs                 | http(s) and bare `www.` links                                 |
| Phone numbers         | International, local Rwandan, and US-style formats           |
| Hashtags              | Social-media style tags                                       |
| Currency amounts       | $, €, £, ¥, and RWF/USD-style amounts                         |

## How to run

Requires Python 3.8+ (standard library only, no dependencies to install).

```bash
python3 src/main.py
```

This will:
1. Read `input/raw-text.txt`
2. Screen every line for malicious/injection content (see below)
3. Run all six extraction patterns against the safe remainder
4. Print a console summary
5. Write the full structured report to `output/sample-output.json`

## Input design

`input/raw-text.txt` is written as a realistic support-ticket export: mixed
formatting, inconsistent phone number styles, a typo'd lookalike domain, a
Visa test card number, multiple currencies, HTML fragments, and — critically
— one ticket (`#10235`) deliberately containing hostile payloads (a `<script>`
tag, a SQL-injection fragment, a path-traversal attempt, an inline event
handler, and raw unmasked card numbers) to prove the security layer actually
rejects them rather than just working on "nice" input.

## Regex patterns, explained

- **Emails** — `[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}`
  A practical (not full RFC-5322) pattern bounded by length limits on both the
  local part and domain, to avoid runaway matching on adjacent garbage text.
  After extraction, each address is separately checked against three ALU
  domain rules, most-specific first (`si.alueducation.com` and
  `alumni.alueducation.com` before the bare `alueducation.com` check) —
  otherwise a subdomain address would incorrectly also satisfy the generic
  official-domain rule. Output stores a **masked** local-part (domain kept)
  so full addresses aren't dumped into the report.

- **Credit cards** — `(?:\d[ -]?){13,19}` matches 13–19 digit sequences,
  optionally grouped with spaces or dashes the way they appear on receipts.
  Every match is then run through a **Luhn checksum**, which rejects
  digit strings that merely *look* like card numbers but aren't well-formed
  (this is validation, not proof a card is real or active).

- **URLs** — matches `http(s)://` and bare `www.` links, with an explicit
  bounded path/query character class instead of a greedy `.*`, and strips
  trailing sentence punctuation (`.`, `,`, `)`) that regex can otherwise
  accidentally sweep into the match at the end of a sentence.

- **Phone numbers** — covers `+250 788 123 456` style international numbers,
  local `078-234-5566` numbers, US-style `(123) 456-7890` / `123-456-7890`,
  paren + two-group forms like `(0788) 456-789`, and compact landlines like
  `(0252) 573100`. This pattern is deliberately run *after* credit cards are
  found and masked out of a working copy of the text — during testing, a raw
  16-digit card number like `4539 1488 0343 6467` was briefly being partially
  re-matched as a phone number. Removing already-claimed card digits before
  running the phone regex fixed that overlap.

- **Hashtags** — `#[A-Za-z][A-Za-z0-9_]{1,49}` requires the character after
  `#` to be a letter. Without that, ticket references like `Ticket #10231`
  in the sample data were being misread as hashtags — a realistic false
  positive worth guarding against.

- **Currency** — matches symbol-prefixed amounts (`$1,250.00`, `€25.00`,
  `¥3,200`) as well as `RWF 450,000` / `450,000 RWF` style amounts.

## Security considerations

The assignment is explicit that input should never be automatically trusted.
This program treats that as a first-class concern, not an afterthought:

1. **Line-by-line screening before extraction.** Every line is checked
   against a set of known attack signatures — `<script>` tags, inline event
   handlers (`onerror=`, `onmouseover=`), `javascript:` links, SQL-injection
   fragments (`; DROP TABLE`, `UNION SELECT`), `<iframe>` injection, path
   traversal (`../../`), and bulk raw card dumps (multiple 13–19 digit PANs
   on one line) — before any extraction regex ever sees it. Flagged lines
   are quarantined (replaced with a placeholder) so one hostile line can't
   corrupt or hijack processing of the rest of a legitimate document. The
   security log records the **category** of the hit (e.g. `xss_script_tag`,
   `bulk_card_dump`), never the offending text itself.

2. **No payload echoing.** The security log only records *that* a line was
   quarantined and *why* (by category), never the offending text itself.
   Logging the raw payload back out would just relocate the injection risk
   into our own logs/output rather than eliminating it.

3. **Length limits against ReDoS.** Any line longer than 2000 characters is
   rejected outright before being run through extraction regexes. Very long,
   attacker-controlled strings are a classic way to trigger catastrophic
   backtracking in naively written patterns; capping input size is a cheap,
   effective mitigation on top of writing bounded-quantifier patterns.

4. **Sensitive data is masked, not stored, in output.** Full credit card
   numbers are never written to `sample-output.json` — only a Luhn-validated
   flag, the digit length, and a masked `**** **** **** 1234` form. Email
   local-parts are similarly redacted (`g***e@alueducation.com`) while the
   domain is kept so ALU classification remains verifiable. This matches the
   requirement that sensitive data shouldn't be unnecessarily exposed in
   outputs or logs, even in a sample/demo run.

5. **Lookalike domains are not special-cased into passing.** The sample
   input includes `support@aIueducation.com` (capital "I" instead of a
   lowercase "l" — a classic phishing lookalike). The classifier correctly
   buckets it as `external` rather than `alu_official`, since it does not
   literally match `@alueducation.com`. This is intentional: ALU-specific
   validation should be strict about the exact domain string, not "close
   enough."

This is not a full security system (no sandboxing, no rate limiting, no
encryption at rest) — but it demonstrates the required defensive mindset:
input is screened before use, sensitive values are minimized on the way out,
and known attack shapes are actively rejected rather than passed through.

## Output

See `output/sample-output.json` for a real run against `input/raw-text.txt`,
containing the security summary (what was quarantined and why) and the full
extracted/classified data set.

## Notes for grading / reuse

- Repo folder name follows the required convention:
  `alu-regex-data-extraction_shyakaalex`.
- The extraction functions in `src/main.py` are pure and can be imported/
  reused independently of the CLI `main()` entry point if needed.
