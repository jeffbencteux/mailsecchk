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
    exit 0
}

log()
{
	echo "$1"

	if [ "$logfile" != "" ]; then
		echo "$1" >> "$logfile"
	fi
}

print_good()
{
	echo "\e[1;32m[+]\e[0m $1"

	if [ "$logfile" != "" ]; then
		echo "[+] $1" >> "$logfile"
	fi
}


print_bad()
{
	echo "\e[1;31m[-]\e[0m $1"

	if [ "$logfile" != "" ]; then
		echo "[-] $1" >> "$logfile"
	fi
}

print_medium()
{
	echo "\e[1;33m[~]\e[0m $1"

	if [ "$logfile" != "" ]; then
		echo "[~] $1" >> "$logfile"
	fi
}

print_info()
{
	echo "\e[1;34m[I]\e[0m $1"

	if [ "$logfile" != "" ]; then
		echo "[I] $1" >> "$logfile"
	fi
}

d=""
dkim_selectors_file="./dkim_selectors.txt"
m365=0

while getopts "d:hl:" o; do
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

has_m365()
{
	m365=0

	if echo "$mx" | grep -q "mail.protection.outlook.com"; then
		print_info "It looks like domain is using Microsoft 365, including specific tests."
		m365=1
	fi
}

get_spf()
{
	domain="$1"

	spf=$(dig +short txt "$domain" | grep 'spf')
}

has_spf()
{
	spf="$1"

	if [ "$spf" = "" ]; then
		print_bad "No SPF for domain"
	else
		print_good "domain has a SPF record"
	fi
}

loose_spf()
{
	spf="$1"

	if [ "$spf" = "" ]; then
		return
	fi

	if echo "$spf" | grep -vq "\-all"; then
		print_bad "SPF not in FAIL mode (\"-all\")"
	else
		print_good "SPF is in FAIL mode (\"-all\")"
	fi
}

spf_include_m365()
{
	spf="$1"

	if [ "$spf" = "" ]; then
		return
	fi

	if [ $m365 -eq 1 ]; then
		if echo "$spf" | grep -vq "include:spf.protection.outlook.com"; then
			print_medium "Microsoft 365 SPF not in includes"
		else
			print_good "SPF includes Microsoft 365 one"
		fi
	fi
}

# DMARC checks
get_dmarc()
{
	domain="$1"

	dmarc=$(dig +short txt "_dmarc.$domain")
}

has_dmarc()
{
	dmarc="$1"

	if [ "$dmarc" = "" ]; then
		print_bad "No dmarc for domain"
	else
		print_good "domain has a DMARC record"
	fi
}

loose_dmarc_policy()
{
	dmarc="$1"

	if [ "$dmarc" = "" ]; then
		return
	fi

	if echo "$dmarc" | grep -Eq "[ ;]p=(reject|quarantine)"; then
		print_good "DMARC policy is correct"
	else
		print_bad "DMARC policy not set to \"reject\" or \"quarantine\""
	fi
}

loose_dmarc_subpolicy()
{
	dmarc="$1"

	if [ "$dmarc" = "" ]; then
		return
	fi


	if echo "$dmarc" | grep "sp=" | grep -vEq "sp=(reject|quarantine)"; then
		print_bad "DMARC subpolicy not set to \"reject\" or \"quarantine\""
	else
		print_good "DMARC subpolicy is correct"
	fi
}

dmarc_pct()
{
	dmarc="$1"

	if [ "$dmarc" = "" ]; then
		return
	fi

	if echo "$dmarc" | grep "pct=" | grep -vEq "pct=100"; then
		print_bad "DMARC sample percentage not set to 100"
	fi
}

dmarc_rua_ruf()
{
	dmarc="$1"

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

dkim_m365()
{
	if [ $m365 -eq 0 ]; then
		return
	fi

	s1=$(dig +short txt "selector1._domainkey.$d" | grep "v=DKIM")
	s2=$(dig +short txt "selector2._domainkey.$d" | grep "v=DKIM")

	if [ "$s1" != "" ] || [ "$s2" != "" ]; then
		print_good "DKIM Microsoft 365 selector set: $s1 $s2"
	else
		print_bad "DKIM Microsoft 365 selectors not set while MS365 is used"
	fi
}

dkim_well_known()
{
	log "Trying well-known selectors..."

	while read -r s; do
		print_info "$s"

		dkim=$(dig +short txt $s._domainkey.$d | grep "v=DKIM")

		if [ "$dkim" != "" ]; then
			print_good "DKIM found with selector $s: $dkim"
			return
		fi
	done < "$dkim_selectors_file"

	print_medium "DKIM could not be found, try obtaining a valid selector for manual review."
}

if [ "$d" = "" ]; then
	echo "No domain provided."
	usage
	exit 1
fi

echo "Checking \e[1;32m$d\e[0m"
echo

# Preliminary checks
get_mx "$d"

if [ "$mx" = "" ]; then
	log "No MX record for domain, are you sure it is used for mail communications?"
else
	log "MX: $mx"
fi
log ""

has_m365 "$d"
log ""

# SPF checks
get_spf "$d"

log "SPF: $spf"
log ""

has_spf "$spf"
loose_spf "$spf"
spf_include_m365 "$spf"

log ""

# DMARC checks
get_dmarc "$d"

log "DMARC: $dmarc"
log ""

has_dmarc "$dmarc"
loose_dmarc_policy "$dmarc"
loose_dmarc_subpolicy "$dmarc"
dmarc_pct "$dmarc"
dmarc_rua_ruf "$dmarc"

log ""

# DKIM checks
log "DKIM:"
log ""

dkim_m365

if [ "$m365" -eq 0 ]; then
	dkim_well_known
fi
