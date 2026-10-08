# Contributing

This repository holds Sigma detection rules for an authorised home SOC lab.
Rules are added through pull requests and reviewed before merge. Keep everything
lab-scoped and vendor-neutral.

## Adding a Rule

1. Pick the folder that matches the telemetry: `rules/windows`, `rules/linux`,
   `rules/network`, `rules/web` or `rules/cloud`.
2. Name the file after the behaviour and its primary data source, in
   `snake_case`, ending in `.yml` - for example `encoded_powershell_4104.yml`.
3. Copy an existing rule as a starting point and generate a fresh UUIDv4 for the
   `id` (for example `python3 -c "import uuid; print(uuid.uuid4())"`). Never
   reuse or edit an `id` once it has been merged.
4. Use only documented log fields (Windows / Sysmon event IDs, auditd record
   fields, Zeek log fields, web access log fields). Do not invent field names.

## Required Fields

Every rule must include, in this order where practical:

- `title`, `id`, `status`, `description`, `references`
- `author`, `date` (ISO 8601 `YYYY-MM-DD`), `tags` (ATT&CK tactic + technique)
- `logsource` (at least one of `product`, `service`, `category`)
- `detection` with named selections and a `condition`
- `falsepositives` (a list, never empty)
- `level` (`informational` | `low` | `medium` | `high` | `critical`)

## Before You Open a PR

- Run `sigma check rules/` - the rule must parse with no errors.
- Convert it with `sigma convert -t splunk rules/<path>` (or another backend) to
  confirm it translates cleanly.
- Add a **test note**: how the rule was fired, ideally the Atomic Red Team test
  for the mapped technique, run in the isolated lab (see `docs/testing.md`).
- Add a **false-positive assessment**: the realistic benign triggers and how a
  deployment would tune or allowlist them. The `falsepositives` field must
  reflect this.

## Conventions

- Plain ASCII only - no em-dashes, no smart quotes, no secrets.
- Use RFC 5737 addresses (`192.0.2.0/24`) and `example.com` in any example.
- One detection concept per rule; keep selections readable and commented where
  the logic is not obvious.

A rule without a test note and a false-positive assessment will not be merged.
