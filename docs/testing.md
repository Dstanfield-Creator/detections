# Testing and Validating Rules

This guide covers validating Sigma rules locally before they are committed, and
generating safe test telemetry in the isolated home lab. Everything here is
lawful and authorised against my own equipment.

## 1. Install the tooling

`sigma-cli` (which bundles the pySigma engine) is the quickest way to check and
convert rules:

```bash
pipx install sigma-cli
sigma version
```

Add the backend plugins you intend to convert to:

```bash
sigma plugin install splunk
sigma plugin install elasticsearch
```

## 2. Validate the rules

Parse every rule and check it against the Sigma schema:

```bash
sigma check rules/
```

`sigma check` reports schema violations, unknown fields and duplicate IDs. Fix
any finding before moving on. A quick YAML-only sanity check without the full
toolchain: `python3 -c "import glob,yaml; [yaml.safe_load(open(f)) for f in glob.glob('rules/**/*.yml', recursive=True)]"`.

## 3. Convert to a backend query

Confirm each rule translates cleanly to the query language of your SIEM:

```bash
sigma convert -t splunk rules/windows/encoded_powershell_4104.yml
sigma convert -t elasticsearch rules/web/sqli_error_pattern.yml
```

A rule that fails to convert usually has a `logsource` or field that the backend
pipeline does not map - adjust and re-run.

## 4. Generate safe test telemetry

Prove the rule fires end to end by executing the mapped ATT&CK technique in an
isolated, snapshotted lab VM using
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team). Only run
atomics on hosts you own and have authorised, and revert the snapshot afterwards.

Example - test the encoded PowerShell rule (T1059.001):

```powershell
Invoke-AtomicTest T1059.001 -ShowDetails
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

Then confirm the converted query matches the event that technique produced in
the captured lab logs. Map each test back to the rule it exercises:

| Rule                             | Technique | Atomic / test action                 |
| -------------------------------- | --------- | ------------------------------------ |
| encoded_powershell_4104          | T1059.001 | `Invoke-AtomicTest T1059.001`        |
| scheduled_task_creation_4698     | T1053.005 | `Invoke-AtomicTest T1053.005`        |
| linux_reverse_shell_bash         | T1059.004 | `Invoke-AtomicTest T1059.004`        |
| ssh_bruteforce_authlog           | T1110     | repeated failed SSH logins in the lab|

Record the test you ran in the pull request so a reviewer can reproduce it.
