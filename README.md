# mailsecchk

A simple POSIX script for mail security checks against domain names.

```
Usage: ./mailsecchk.sh [OPTIONS]...
check mail security of a given domain

arguments:
  -d domain to be checked
  -h display this help and exit
  -l log file to output to
```

## Current checks

* SPF DNS record presence
* SPF not using FAIL mode "-all"
* DMARC DNS record presence
* DMARC policy ("p")
* DMARC subpolicy ("sp")
* DMARC sample percentage ("pct")
* DMARC aggregation and forensic reports send to third-parties ("rua" and "ruf")
* DKIM dictionnary guess for selectors (list is in dkim_selectors.txt)

Specific to Microsoft 365:

* SPF set to include M365 SPF
* DKIM presence (selectors are predictable)

## Examples

![example 1](img/altf8.png "Example 1")

![example 2](img/lemonde.png "Example 2")
