# GitHub security advisory — field-by-field input

{{advisory_banner}}Open the affected repository → **Security** → **Report a vulnerability**, then copy each
value below into the field of the same name. Everything inside a code box is the exact text
to paste (the description fields accept Markdown).

## Title

```text
{{advisory_title}}
```

## Summary

````markdown
{{summary}}
````

## Details

````markdown
{{advisory_details_md}}
````

## Proof of concept

````markdown
{{advisory_poc_md}}
````

## Impact

````markdown
{{advisory_impact}}
````

## Affected products

| Field | Value |
|---|---|
| Ecosystem | `{{advisory_ecosystem}}` |
| Package name | `{{advisory_package}}` |
| Affected versions | `{{advisory_affected}}` |
| Patched versions | {{advisory_patched}} |

## Severity

| Field | Value |
|---|---|
| Severity | {{cvss_severity}} ({{cvss_score}}) — choose "Assess severity using CVSS" and paste the vector |
| Vector string | `{{cvss_vector}}` |

## Weaknesses

{{advisory_cwes_md}}

## "I used AI assistance to find or write up this report"

{{advisory_ai}}
