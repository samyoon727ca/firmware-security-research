# Security memo: {{title}}

{{memo_banner}}| | |
|---|---|
| **To** | {{recipient}} |
| **From** | {{researcher}}{{contact}} |
| **Tracking** | {{tracking}} |
| **Validated** | {{validated_date}} |
| **Severity** | CVSS v3.1 {{cvss_score}} ({{cvss_severity}}) — `{{cvss_vector}}` · {{cwe}} {{cwe_name}} |
| **Component** | {{component}} |
| **Handling** | Confidential until a fix is published or {{target_public}} |

## What is wrong

{{summary}}

## Affected

{{affected_md}}

## Steps to reproduce

Preconditions: {{preconditions}}

{{memo_steps_md}}

## Proof of concept

For verification on a build you run yourself. Do not point it at a system you do not operate.

{{poc_md}}

## Fix

{{remediation}}
