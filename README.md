# mailsecchk

A simple shell script (almost) POSIX(1) for mail security checks against domain names.

```
Usage: ./mailsecchk.sh [OPTIONS]...
check mail security of a given domain

arguments:
  -d domain to be checked
  -h display this help and exit
  -l log file to output to
  -p extract DKIM public key if found
  -r SPF recursive tests
```

(1): not POSIX anymore as keyword "local" is used, but it should work on most UNIX.

## Current checks

* SPF DNS record presence
* SPF version
* SPF not using FAIL mode "-all"
* SPF include not resolving to a correct DNS TXT record (potential domain takeover)
* DMARC DNS record presence
* DMARC version
* DMARC policy ("p")
* DMARC subpolicy ("sp")
* DMARC sample percentage ("pct")
* DMARC aggregation and forensic reports send to third-parties ("rua" and "ruf")
* DMARC failure report options ("fo")
* DMARC SPF and DKIM alignment set to relaxed mode (see [there](https://www.bencteux.fr/posts/dmarc_relax/) for why)
* DKIM dictionnary guess for selectors (list is in dkim_selectors.txt)
* DKIM public key size (if public key extraction is enabled)
* MTA-STS DNS record presence
* MTA-STS DNS record version
* MTA-STS HTTPS policy presence
* TLS-RPT DNS record presence
* TLS-RPT version
* TLS-RPT reports send to third-parties ("rua")
* DANE TLSA records presence for each MX entry

Checks for specific mail providers:

* SPF set to include mail provider SPF
* DKIM presence (selectors are often predictable)

Currently included providers:

* Microsoft 365
* Google workspace
* Amazon SES

Other features

* DKIM public key extraction if selector is found
* Recursive checks on SPF includes

Note: if recursion on SPF includes is not enabled, you may end up with false positives on wether a mail provider SPF is included for a domain or not.

## Examples

![example 1](img/altf8.png "Example 1")

![example 2](img/lemonde.png "Example 2")
