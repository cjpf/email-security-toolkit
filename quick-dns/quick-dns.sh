#!/bin/bash

# QUICK-DNS.sh
: Description: Quickly obtain info about a domain, such as MX records, SPF, DMARC, RBL stats, and other info.
: Author: Zachary Puhl
: Contact: zpuhl@barracuda.com // postmaster@yeethop.xyz
: Date: 05 March, 2019
##############

# Initial function declarations:
function usage() {
    echo "USAGE: $0 \"domain.name\""
    echo " Get information about \"domain.name\" such as SPF, MX records,"
    echo "  associated IPs, DMARC, RBL stats, and other info."
    echo
    exit 1
}

function noNameServers() {
    echo "ERROR: $0: Domain \"${DOMAIN}\" does not have any valid name servers!"
    exit 2
}

function lookupIP () {
    BRBL_LOOKUP=
    for i in {4..1}; do BRBL_LOOKUP="${BRBL_LOOKUP}`echo "${A_RECORD}" | cut -d'.' -f${i}`."; done
    BRBL_LOOKUP="${BRBL_LOOKUP}b.barracudacentral.org"
    IS_LISTED=$(dig a +short ${BRBL_LOOKUP})
    if [ -n "$IS_LISTED" ]; then echo "${TC_RED}[LISTED]${TC_NORMAL}"; else echo "${TC_GREEN}[NOT LISTED]${TC_NORMAL}"; fi
}

# Set up colors, if they're supported by the current terminal.
COLORS=$(tput colors 2>/dev/null)i
if [ -n "$COLORS" ]; then
    TC_RED=`tput setaf 1 2>/dev/null`
    TC_GREEN=`tput setaf 2 2>/dev/null`
    TC_YELLOW=`tput setaf 3 2>/dev/null`
    TC_BLUE=`tput setaf 4 2>/dev/null`
    TC_CYAN=`tput setaf 6 2>/dev/null`
    TC_NORMAL=`tput sgr0 2>/dev/null`
    TC_BOLD=`tput bold 2>/dev/null`
fi



# Ensure that ARG1 exists and that it has a domain-name format.
[[ -z "$1" || -z `echo "$1" | grep -Poi '^([a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,})'` ]] && usage

# Set up some initial variables.
DOMAIN="$1"
NAME_SERVER=$(dig ns +short $DOMAIN | head -1)

# Check to make sure name-server exists and is a valid host. If it's not, fail out.
[[ -z "${NAME_SERVER}" || -z `host ${NAME_SERVER} | grep -Pv '(NXDOMAIN)|not found'` ]] && noNameServers
echo "${TC_WHITE}Primary Nameserver${TC_NORMAL}: ${NAME_SERVER}"

# Get the SPF record(s) for the domain.
SPF_RECORD=$(dig txt +short $DOMAIN @${NAME_SERVER} | grep "v=spf1")
[ -z "$SPF_RECORD" ] && SPF_RECORD="NONE"
echo "${TC_CYAN}SPF Record${TC_NORMAL}: ${SPF_RECORD}"

# Get the DMARC record for the domain.
DMARC_RECORD=$(dig txt +short _dmarc.${DOMAIN} @${NAME_SERVER} | head -1 | sed 's/\\//g')
[ -z "$DMARC_RECORD" ] && DMARC_RECORD="NONE"
echo "${TC_RED}DMARC Record${TC_NORMAL}: ${DMARC_RECORD}"

# Get the MX record(s) for the domain.
MX_RECORDS=$(dig mx +short $DOMAIN @${NAME_SERVER} | sed -r 's/^/\t/g')
MX_RECORD_OUT=
for hostname in $MX_RECORDS; do
    if [[ "$hostname" =~ '^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}\.?$' \
    || -n `echo "$hostname" | grep -Poi '^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}\.?$'` ]]; then
        # It's an FQDN. The dig should be done against a public DNS since the FQDN can be for a different domain.
        hostname="${hostname} (Resolved IP: `dig a +short ${hostname} @8.8.8.8 | head -1`)\n"
    elif [[ "$hostname" =~ '^(\d{1,3}\.){3}\d{1,3}$' || "$hostname" =~ '^([0-9a-fA-F]{1,4})(::?[0-9a-fA-F]{1,4}){1,5}$' \
    || -n `echo "$hostname" | grep -Poi '^(\d{1,3}\.){3}\d{1,3}$'` \
    || -n `echo "$hostname" | grep -Poi '^([0-9a-fA-F]{1,4})(::?[0-9a-fA-F]{1,4}){1,5}$'` ]]; then
        # MX host is already an IPv4 or IPv6 address.
        hostname="${hostname}\n"
    else
        # It's either the priority number, or it's something else invalid.
        hostname="${hostname} "
    fi
    # Append the new hostname variable onto the output of the MX record.
    MX_RECORD_OUT="${MX_RECORD_OUT}${hostname}"
done

[ -z "$MX_RECORDS" ] && MX_RECORDS="NONE"
echo -e "${TC_GREEN}MX Record(s)${TC_NORMAL}:\n${MX_RECORD_OUT}"


# Begin RBL Check
echo "Attempting A-record RBL check..."
A_RECORD=$(host $DOMAIN | grep -v 'IPv6' | head -n1 | awk '{print $4}')
if [ -z "${A_RECORD}" ]; then
    echo "DNS A-Record for ${A_RECORD} isn't defined..."
else
    printf "Checking Barracuda RBL for the web server IP address (${A_RECORD})... "
    lookupIP "${A_RECORD}"
fi

echo

# RBL Check on Mail Servers in MX records.
echo "Attempting MX-record RBL check..."
for i in $(host $DOMAIN | grep -Po 'mail is handled by \d+ (.*)$' | grep -Poi '([a-z0-9\-]+\.)+' | tr '\n' ' '); do
    if [[ ! i =~ '^(\d+\.){3}\d+\.?$' ]]; then
        A_RECORD=$(host $i | grep -v 'IPv6' | head -n1 | awk '{print $4}')
    else A_RECORD="$i"; fi
    printf "Checking Barracuda RBL for the mail server IP address (${A_RECORD})... "
    lookupIP "${A_RECORD}"
done

exit 0
