#!/bin/sh
# Copyright (c) 2022, Jeffrey Bencteux
# All rights reserved.

# This source code is licensed under the GPLv3 license found in the
# LICENSE file in the root directory of this source tree.

usage()
{
    echo "Usage: $0 [OPTIONS]..."
    echo "check mail security of a given domain"
    echo
    echo "arguments:"
    echo "  -d domain to be checked"
    echo "  -h display this help and exit"
    echo "  -l log file to output to"
    echo "  -p extract DKIM public key if found"
    echo "  -r SPF recursive tests"
    exit 0
}

log()
{
	printf '%b\n' "$1"

	if [ "$logfile" != "" ]; then
		echo "$1" >> "$logfile"
	fi
}

print_good()
{
	printf '\033[1;32m[+]\033[0m %s\n' "$1"

	if [ "$logfile" != "" ]; then
		echo "[+] $1" >> "$logfile"
	fi
}


print_bad()
{
	printf '\033[1;31m[-]\033[0m %s\n' "$1"

	if [ "$logfile" != "" ]; then
		echo "[-] $1" >> "$logfile"
	fi
}

print_medium()
{
	printf '\033[1;33m[~]\033[0m %s\n' "$1"

	if [ "$logfile" != "" ]; then
		echo "[~] $1" >> "$logfile"
	fi
}

print_info()
{
	printf '\033[1;34m[I]\033[0m %s\n' "$1"

	if [ "$logfile" != "" ]; then
		echo "[I] $1" >> "$logfile"
	fi
}

d=""
spf_recursive=0
spf_specific_found=0
dkim_selectors_file="./dkim_selectors.txt"
dkim_extract=0
dkim_key_outfile="./dkim_pubkey.pem"
# Quite a hard choice of what is a good key size here, for now keeping to < 2048 bits
dkim_key_minsize=2048
specific=""
bimi_selectors_file="./bimi_selectors.txt"

while getopts "d:hl:pr" o; do
    case "${o}" in
	d)
	    d="${OPTARG}"
	    ;;
        h)
            usage
            ;;
	l)
	    logfile="${OPTARG}"
	    ;;
	p)
	    dkim_extract=1
	    ;;
	r)
	    spf_recursive=1
	    ;;
        *)
	    usage
	    ;;
    esac
done
shift $((OPTIND-1))

log "  _   .-')      ('-.                         .-')      ('-.                        ('-. .-..-. .-')   "
log " ( '.( OO )_   ( OO ).-.                    ( OO ).  _(  OO)                      ( OO )  /\\  ( OO )  "
log " ,--.   ,--.) / . --. /  ,-.-')  ,--.     (_)---\\_)(,------.   .-----.   .-----. ,--. ,--.,--. ,--.  "
log " |   \`.'   |  | \\-.  \\   |  |OO) |  |.-') /    _ |  |  .---'  '  .--./  '  .--./ |  | |  ||  .'   /  "
log " |         |.-'-'  |  |  |  |  \\ |  | OO )\\  :\` \`.  |  |      |  |('-.  |  |('-. |   .|  ||      /, "
log " |  |'.'|  | \\| |_.'  |  |  |(_/ |  |\`-' | '..\`''.)(|  '--.  /_) |OO  )/_) |OO  )|       ||     ' _) "
log " |  |   |  |  |  .-.  | ,|  |_.'(|  '---.'.-._)   \\ |  .--'  ||  |\`-'| ||  |\`-'| |  .-.  ||  .   \\   "
log " |  |   |  |  |  | |  |(_|  |    |      | \\       / |  \`---.(_'  '--'\\(_'  '--'\\ |  | |  ||  |\\   \\  "
log " \`--'   \`--'  \`--' \`--'  \`--'    \`------'  \`-----'  \`------'   \`-----'   \`-----' \`--' \`--'\`--' '--'  "

get_mx()
{
	domain="$1"

	mx=$(dig +short mx "$domain")
}

has_mx_specific()
{
	local name="$1"
	local full_name="$2"
	local mx_dn="$3"

	if echo "$mx" | grep -q "$mx_dn"; then
		print_info "It looks like domain is using $full_name, including specific tests."
		specific="$name"
	fi
}

get_spf()
{
	local domain="$1"

	spf=$(dig +short txt "$domain" | grep 'spf')
}

has_spf()
{
	local spf="$1"

	if [ "$spf" = "" ]; then
		print_bad "No SPF for domain"
	else
		print_good "domain has a SPF record"
	fi
}

spf_version()
{
	local spf="$1"

	if [ "$spf" = "" ]; then
		return
	fi

	if echo "$spf" | grep -Eqv "^\"(v=spf1[ ]|^\"v=spf1$)"; then
		print_bad "SPF version is incorrect"
	else
		print_good "SPF version is correct"
	fi
}

loose_spf()
{
	local spf="$1"

	if [ "$spf" = "" ]; then
		return
	fi

	if echo "$spf" | grep -vq "\-all"; then
		print_bad "SPF not in FAIL mode (\"-all\")"
	else
		print_good "SPF is in FAIL mode (\"-all\")"
	fi
}

spf_include_domain()
{
	local spf="$1"
	local name="$2"
	local full_name="$3"
	local include="$4"
	local found_in_mx="$5"

	if [ "$spf" = "" ]; then
		return
	fi

	if [ "$found_in_mx" != "$name" ]; then
		return
	fi

	if echo "$spf" | grep -q "include:$include"; then
		print_good "SPF includes $name one ($include)"
		spf_specific_found=1
		spf_specific_include="$include"
	fi
}

spf_includes_recursive()
{
	local spf="$1"
	local domain="$2"
	local specific="$3"

	if [ "$spf_recursive" -eq 0 ]; then
		return
	fi

	if [ "$spf" = "" ]; then
		return
	fi

	# Unsure this weak parsing catches all cases
	spf_includes=$(echo "$spf" | grep -Eo "include:[^ ]+" | sed 's/include://g')

	if [ "$spf_includes" != "" ]; then
		print_info "SPF recursive check for $domain"
	fi


	for include in $spf_includes; do
		include_res=$(dig +short txt "$include" | grep "spf")

		if [ "$include_res" = "" ]; then
			print_bad "SPF include \"$include\" does not resolve to a valid DNS TXT record"
		else
			print_info "\"$include\": $include_res"
			spf_include_domain "$include_res" "m365" "Microsoft 365" "spf.protection.outlook.com" "$specific"
			spf_include_domain "$include_res" "google" "Google Workspace" "_spf.google.com" "$specific"
			spf_includes_recursive "$include_res" "$include" "$specific"
		fi
	done
}

# DMARC checks
get_dmarc()
{
	local domain="$1"

	dmarc=$(dig +short txt "_dmarc.$domain")
}

has_dmarc()
{
	local dmarc="$1"

	if [ "$dmarc" = "" ]; then
		print_bad "No dmarc for domain"
	else
		print_good "domain has a DMARC record"
	fi
}

dmarc_version()
{
	local dmarc="$1"

	if [ "$dmarc" = "" ]; then
		return
	fi


	if echo "$dmarc" | grep -Eq "^\"v=DMARC1"; then
		print_good "DMARC version is correct"
	else
		print_bad "DMARC version is incorrect, all record will be ignored by receivers"
	fi
}

loose_dmarc_policy()
{
	local dmarc="$1"

	if [ "$dmarc" = "" ]; then
		return
	fi

	loose_dmarc_p=0

	if echo "$dmarc" | grep -Eq "[ ;]p=(reject|quarantine)"; then
		print_good "DMARC policy is correct"
	else
		print_bad "DMARC policy not set to \"reject\" or \"quarantine\""
		loose_dmarc_p=1
	fi
}

loose_dmarc_subpolicy()
{
	local dmarc="$1"

	if [ "$dmarc" = "" ]; then
		return
	fi


	if echo "$dmarc" | grep "sp=" | grep -vEq "sp=(reject|quarantine)"; then
		print_bad "DMARC subpolicy not set to \"reject\" or \"quarantine\""
	else
		if [ "$loose_dmarc_p" -eq 1 ]; then
			print_bad "DMARC subpolicy not set to \"reject\" or \"quarantine\""
		else
			print_good "DMARC subpolicy is correct"
		fi
	fi
}

dmarc_pct()
{
	local dmarc="$1"

	if [ "$dmarc" = "" ]; then
		return
	fi

	if echo "$dmarc" | grep "pct=" | grep -vEq "pct=100"; then
		print_bad "DMARC sample percentage not set to 100"
	fi
}

dmarc_rua_ruf()
{
	local dmarc="$1"

	if [ "$dmarc" = "" ]; then
		return
	fi

	rua=$(echo "$dmarc" | grep -oE "rua=[^ ]+";)
	ruf=$(echo "$dmarc" | grep -oE "ruf=[^ ]+";)

	if [ "$rua" = "" ]; then
		print_medium "DMARC no aggregate report URI (RUA) defined"
	else
		if echo "$rua" | grep -Eo "@[^ ,\"]+" | grep -vq "$d"; then
			print_medium "DMARC RUA is external to the domain, please review manually"
		fi
	fi

	if [ "$ruf" = "" ]; then
		print_medium "DMARC no forensic report URI (RUF) defined"
	else
		if echo "$ruf" | grep -Eo "@[^ ,\"]+" | grep -vq "$d"; then
			print_medium "DMARC RUF is external to the domain, please review manually"
		fi
	fi
}

dmarc_fo()
{
	local dmarc="$1"

	if [ "$dmarc" = "" ]; then
		return
	fi

	fo=$(echo "$dmarc" | grep -oE "fo=[^ ;]")

	# FO defaults to 0, handling below the case where it is not specified but there is a ruf
	if [ "$fo" = "" ]; then
		if [ "$ruf" != "" ]; then
			print_medium "Failure reporting options set to report only if all mechanisms fail (fo=0)"
		fi
		return
	fi

	if echo "$fo" | grep -qEv "fo=[01ds:]+"; then
		print_bad "Failure reporting options set to unknown value (!= 0,1,d,s)"
		return
	fi

	fo_val=$(echo "$fo" | grep -oE "[01ds]")

	if echo "$fo_val" | grep -Eq "0"; then
		print_medium "Failure reporting options set to report only if all mechanisms fail (fo=0)"
	fi

	if echo "$fo_val" | grep -Eq '1'; then
		print_good "Failure reporting options set to 1 (fo=1)"
	fi

	# 'd' and 's' options may produce a lot of false positives. Leaving them out of the rule for now.
}

dmarc_id_alignment()
{
	local dmarc="$1"
	local id="$2"

	if [ "$dmarc" = "" ]; then
		return
	fi

	if echo "$dmarc" | grep -q "$id=s"; then
		print_good "DMARC Identifier alignment in strict mode (\"$id=s\")"
	else
		print_medium "DMARC Identifier alignment in relaxed mode (\"$id=r\")"
	fi
}

dkim_specific()
{
	local name="$1"
	local full_name="$2"
	local selectors="$3"

	if [ "$specific" != "$name" ]; then
		return
	fi

	for s in $selectors; do
		local curr="$(dig +short txt "$s._domainkey.$d" | grep "v=DKIM")"

		if [ "$curr" != "" ]; then
			print_good "DKIM $full_name set ($s)"
			dkim="$curr"
		fi
	done

	if [ "$dkim" = "" ]; then
		print_bad "DKIM $full_name selectors not set while $full_name is used"
	fi
}

dkim_well_known()
{
	log "Trying well-known selectors..."

	while read -r s; do
		print_info "$s"

		dkim=$(dig +short txt "$s._domainkey.$d" | grep "v=DKIM")

		if [ "$dkim" != "" ]; then
			print_good "DKIM found with selector $s: $dkim"
			return
		fi
	done < "$dkim_selectors_file"

	print_medium "DKIM could not be found, try obtaining a valid selector for manual review."
}

dkim_extract_key()
{
	if [ "$dkim_extract" -eq 0 ]; then
		return
	fi

	local dkim_p="$(echo "$dkim" | grep -Eo 'p=[^;]+' | sed 's/p=//g' | sed 's/[ "]//g')"

	print_info "Extracting DKIM public key..."

	echo "-----BEGIN PUBLIC KEY-----" > "$dkim_key_outfile"
	echo "$dkim_p" >> "$dkim_key_outfile"
	echo "-----END PUBLIC KEY-----" >> "$dkim_key_outfile"

	dkim_parsed_key=$(openssl rsa -pubin -in "$dkim_key_outfile" -text)

	log "$dkim_parsed_key"
}

dkim_crypto_keysize()
{
	if [ "$dkim_parsed_key" = "" ]; then
		return
	fi

	local keysize="$(echo "$dkim_parsed_key" | grep -E 'Public-Key:[ ]+\([0-9]+[ ]+bit\)' | grep -Eo '[0-9]+')"

	if [ "$keysize" -lt $dkim_key_minsize ]; then
		print_medium "DKIM public key size is < $dkim_key_minsize bits ($keysize bits)"
	else
		print_good "DKIM public key size is correct ($keysize bits)"
	fi
}

get_mta_sts()
{
	local domain="$1"

	mta_sts=$(dig +short txt "_mta-sts.$domain")
}

has_mta_sts()
{
	local mta_sts="$1"

	if [ "$mta_sts" = "" ]; then
		print_medium "MTA-STS record not defined"
	else
		print_good "MTA-STS record exists"
	fi
}

mta_sts_version()
{
	local mta_sts="$1"

	if [ "$mta_sts" = "" ]; then
		return
	fi

	if echo "$mta_sts" | grep -q "v=STSv1"; then
		print_good "MTA-STS version is correct"
	else
		print_bad "MTA-STS version incorrect"
	fi
}

mta_sts_policy()
{
	local domain="$1"

	if [ "$mta_sts" = "" ]; then
		return
	fi

	mta_sts_policy=$(curl -s "https://mta-sts.$domain/.well-known/mta-sts.txt")

	if [ "$mta_sts_policy" = "" ]; then
		print_bad "MTA-STS no policy available at https://mta-sts.$domain/.well-known/mta-sts.txt"
	else
		print_good "MTA-STS policy available:"
		log ""
		log "$mta_sts_policy"
		log ""
	fi
}

get_tls_rpt()
{
	local domain="$1"

	tls_rpt=$(dig +short txt "_smtp._tls.$domain")
}

has_tls_rpt()
{
	tls_rpt="$1"

	if [ "$tls_rpt" = "" ]; then
		print_medium "TLS-RPT record not defined"
	else
		print_good "TLS-RPT record found"
	fi
}

tls_rpt_version()
{
	tls_rpt="$1"

	if [ "$tls_rpt" = "" ]; then
		return
	fi

	if echo "$tls_rpt" | grep -q "v=TLSRPTv1"; then
		print_good "TLS-RPT version is correct"
	else
		print_bad "TLS-RPT version incorrect"
	fi
}

tls_rpt_third_party()
{
	domain="$1"
	tls_rpt="$2"

	if [ "$tls_rpt" = "" ]; then
		return
	fi

	rua=$(echo "$dmarc" | grep -oE "rua=[^ ]+";)

	if echo "$rua" | grep -Eo "@[^ ,\"]+" | grep -vq "$d"; then
		print_medium "TLS-RPT reports sent to third-parties, please review manually"
	fi
}

dane_tlsa_rec()
{
	domain="$1"
	port="$2"

	if [ "$domain" = "" ]; then
		return
	fi

	tlsa_rec=$(dig +short tlsa "_$port._tcp.$domain")

	if [ "$tlsa_rec" = "" ]; then
		print_bad "DANE no TLSA record for $domain"
		return
	fi

	print_good "DANE TLSA record for $domain: \"$tlsa_rec\""
}

dane()
{
	mx="$1"

	if [ "$mx" = "" ]; then
		return
	fi

	mx_names=$(echo "$mx" | awk '{print $2}')

	for entry in $mx_names; do
		# Only testing port 25 for now, might be necessary to add more
		dane_tlsa_rec "$entry" "25"
	done
}

get_bimi()
{
	local domain="$1"
	local selectors="$2"

	log "Trying well-known selectors..."

	while read -r s; do
		print_info "$s"
		local curr="$(dig +short txt "$s._bimi.$d" | grep "v=BIMI")"

		if [ "$curr" != "" ]; then
			print_good "BIMI found for selector $s: $curr"
			bimi="$curr"
		fi
	done < "$bimi_selectors_file"
}

has_bimi()
{
	local bimi="$1"

	if [ "$bimi" = "" ]; then
		print_info "BIMI record not defined"
	else
		print_good "BIMI record exists"
	fi
}

bimi_version()
{
	local bimi="$1"

	if [ "$bimi" = "" ]; then
		return
	fi

	if echo "$bimi" | grep -q "v=BIMI1"; then
		print_good "BIMI version is correct"
	else
		print_bad "BIMI version incorrect"
	fi
}

if [ "$d" = "" ]; then
	echo "No domain provided."
	usage
	exit 1
fi

log "Checking \033[1;32m$d\033[0m"
log

# Preliminary checks
get_mx "$d"

if [ "$mx" = "" ]; then
	log "No MX record for domain, are you sure it is used for mail communications?"
else
	log "MX: $mx"
fi
log ""

has_mx_specific "m365" "Microsoft 365" "mail.protection.outlook.com"
has_mx_specific "google" "Google Workspace" "aspmx.l.google.com"
has_mx_specific "amazon" "Amazon SES" "amazonaws.com"
has_mx_specific "ovh" "OVH Cloud" "mail.ovh.net"
log ""

# SPF checks
get_spf "$d"

log "SPF: $spf"
log ""

has_spf "$spf"
spf_version "$spf"
loose_spf "$spf"
spf_include_domain "$spf" "m365" "Microsoft 365" "spf.protection.outlook.com" "$specific"
spf_include_domain "$spf" "google" "Google Workspace" "_spf.google.com" "$specific"
spf_include_domain "$spf" "amazon" "Amazon SES" "amazonses.com" "$specific"
spf_include_domain "$spf" "ovh" "OVH Cloud" "mx.ovh.com" "$specific"
spf_includes_recursive "$spf" "$d" "$specific"

# Only at the end of the recursion can we test if specific SPF has not been found
if [ "$specific" != "" ] && [ "$spf_specific_found" -eq 0 ]; then
	print_medium "$specific SPF not in includes ($spf_specific_include)"
fi

log ""

# DMARC checks
get_dmarc "$d"

log "DMARC: $dmarc"
log ""

has_dmarc "$dmarc"
dmarc_version "$dmarc"
loose_dmarc_policy "$dmarc"
loose_dmarc_subpolicy "$dmarc"
dmarc_pct "$dmarc"
dmarc_rua_ruf "$dmarc"
dmarc_fo "$dmarc"
dmarc_id_alignment "$dmarc" "aspf"
dmarc_id_alignment "$dmarc" "adkim"

log ""

# DKIM checks
log "DKIM:"
log ""

dkim_specific "m365" "Microsoft 365" "selector1 selector2"
dkim_specific "google" "Google Workspace" "google"

if [ "$specific" = "" ]; then
	dkim_well_known
fi

if [ "$dkim" != "" ]; then
	dkim_extract_key
	dkim_crypto_keysize
fi

log ""

# MTA-STS checks
get_mta_sts "$d"

log "MTA-STS: $mta_sts"
log ""

has_mta_sts "$mta_sts"
mta_sts_version "$mta_sts"
mta_sts_policy "$d"

log ""

# TLS-RPT checks
get_tls_rpt "$d"

log "TLS-RPT: $tls_rpt"
log ""

has_tls_rpt "$tls_rpt"
tls_rpt_version "$tls_rpt"
tls_rpt_third_party "$d" "$tls_rpt"

log ""

# DANE for SMTP
log "DANE for SMTP:"
log ""

dane "$mx"
log ""

# BIMI
log "BIMI:"
log ""

get_bimi "$d"
has_bimi "$bimi"
bimi_version "$bimi"
