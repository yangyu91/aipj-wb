# Evidence and Reporting

## Initial report template
### 专项补充（安卓内核/网络/Web 目标时必填） / Specialized fields (mandatory for Android-kernel/network/web targets)

**For Android kernel targets:**
- Kernel version: ________
- .ko load address (from /proc/modules): ________
- ioctl command codes: ________ (list with hex values)
- Syscall wrapper logs: ________ (attach excerpt)

```markdown
# Reverse Engineering Initial Report

## Summary
- Artifact:
- Scope:
- Current phase:
- Overall risk:

## Artifact inventory
| Name | Path | Size | SHA-256 | Type | Notes |
|---|---|---:|---|---|---|

## Verified facts
| ID | Evidence | Source/offset/tool | Interpretation | Confidence |
|---|---|---|---|---|

## Key findings
### Finding 1: <title>
- Evidence:
- Impact:
- Confidence:
- Validation status:

## Unknowns
- 

## Recommended next steps
1. 
2. 
3. 
```

## Deep reverse report template

```markdown
# Deep Reverse Engineering Report

## Executive summary
## Scope and artifacts
## Methodology
## Architecture and behavior model
## Function/module map
## Data-flow and trust boundaries
## Dynamic observations
## Vulnerability candidates
## Evidence appendix
## Reproducibility notes
## Recommended next steps
```

## Vulnerability advisory template

```markdown
# Vulnerability Report: <title>

## Summary
## Affected product/version/component
## Severity and rationale
## Preconditions
## Root cause
## Technical details
## Safe reproduction evidence
## Impact
## Remediation guidance
## Detection/mitigation
## Evidence appendix
## Timeline/status
```

## Confidence vocabulary
- **High**: directly observed in code or runtime and reproducible.
- **Medium**: supported by multiple static indicators but not fully executed.
- **Low**: plausible hypothesis with limited evidence.

## Evidence table rules
Use stable identifiers. Include offsets, function names, command outputs, hashes, log excerpts, screenshots, or traces. Keep raw logs in the case directory and summarize only the relevant lines in reports.
- For Android kernel targets, every offset/ioctl code must be accompanied by: source artifact (module name), derivation method (Ghidra/radare2), and verification step.

