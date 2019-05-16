#!/bin/bash

# QUICK-DNS.sh
# Description: Quickly obtain info about a domain, such as MX records, SPF, DMARC, RBL stats, and other info.
# Contributors:
#    Notsoano Nimus <postmaster@thestraightpath.email>,
#    CJ Pfenninger <cjpf@charliejuliet.net>
# Repo: https://github.com/NotsoanoNimus/email-security-toolkit/tree/master/quick-dns
# Date [of first use]: 05 March, 2019
##############

######################################################################################
# quick-dns is a script to simplify the gathering of email-related DNS information.
#
# Copyright (C) 2019 "Notsoano Nimus", as a free software project
#  licensed under GNU GPLv3.
#
# This program is free software: you can redistribute it and/or modify it under
#  the terms of the GNU General Public License as published by the Free Software
#  Foundation, either version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
#  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
#  FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
#  this program. If not, see https://www.gnu.org/licenses/.
######################################################################################


# Main function for the script, where the actual actions are taken.
function quickDNS_main() {
    # Firstly, see if colors are turned off with the optional flag in ARG1, then shift it out.
    [[ "$1" =~ ^-[Nn]$ ]] && NO_COLORS="YES" && shift
    # Terminal color setup and dependency check.
    colors "${NO_COLORS}"
    depCheck "dig host grep awk sed tr printf cut head"

    # Ensure that ARG1 exists and that it has a domain-name format.
    [[ -z "$1" || -z `echo "$1" | grep -Poi '^([a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,})'` ]] && usage

    # DOMAINS: All of the passed domains to the script for multiple runs, if requested.
    DOMAINS="$@"
    # DEFAULT_OPTIONS: Default options for the timeout on the 'dig' lookups that aren't fallback lookups.
    DEFAULT_OPTIONS="+time=2 +tries=2"

    # Begin the main loop.
    #IFS=' '
    for fqdn in ${DOMAINS[@]}; do
        # Run the script for a domain. Start by resetting variables and then crunching the DNS.
        clearVars "NAME_SERVER SPF_RECORD DMARC_RECORD MX_RECORD_OUT MX_RECORDS A_RECORD"
        DOMAIN="${fqdn}"
        echo "################################################################################"
        echo "Checking DNS information for ${TC_BOLD}${TC_YELLOW}${fqdn}${TC_NORMAL}..."

        getNameServers
        getSPF
        getDMARC
        getMX
        RBL_getALookup
        RBL_getMXLookup
        echo
    done
}


################################################################
###################### Pre-Script Modules ######################
################################################################


# Usage information for the script. Terse and easy since this isn't a gargantuan script.
function usage() {
    echo "USAGE: $0 [-N] domain.name [domain.two domain.three ... domain.n]"
    echo " Get information about 'domain.name' such as SPF, MX records,"
    echo "  associated IPs, DMARC, RBL stats, and other email-related info."
    echo
    echo "OPTIONS:"
    echo "    -n    Don't use any colors. This MUST be argument one if used."
    echo "** Multiple space-separated domains can be passed to this script."
    exit 1
}

# Set up the terminal color variables, if supported.
## An optional argument of ANY value is passed to this function to disable colors altogether.
function colors() {
    [ -n "$1" ] && return
    # Set up colors, if they're supported by the current terminal.
    COLORS=$(tput colors 2>/dev/null)
    if [ -n "$COLORS" ]; then
        TC_RED=`tput setaf 1 2>/dev/null`
        TC_GREEN=`tput setaf 2 2>/dev/null`
        TC_YELLOW=`tput setaf 3 2>/dev/null`
        TC_BLUE=`tput setaf 4 2>/dev/null`
        TC_CYAN=`tput setaf 6 2>/dev/null`
        TC_NORMAL=`tput sgr0 2>/dev/null`
        TC_BOLD=`tput bold 2>/dev/null`
    fi
}

# Check for the necessary commands that aren't native to all Linux/UNIX systems.
# ARGS:
#   $1 = string of space-separated dependencies.
function depCheck() {
    # Build a space-separated list of dependencies for this script.
    local DEPENDENCIES="$1"
    # Let the user know what deps are required (off for now).
    #echo "Checking for necessary dependencies: ${TC_BLUE}${DEPENDENCIES}${TC_NORMAL}"
    # Set the separator/delimiter to ' '
    IFS=' '
    # Iterate through each command above and check for its existence in the $PATH variable using the 'command' command.
    for needed in ${DEPENDENCIES[@]}; do
        command -v $needed 2>&1 >/dev/null
        if [ $? -ne 0 ]; then
          echo "${TC_RED}ERROR${TC_NORMAL}: Missing dependency command \"${TC_BLUE}${needed}${TC_NORMAL}\"."
          echo "    Please install this on your local machine and try again."
          exit 255
        fi
    done
}

# Clear all variables associated with the below DNS lookup/parsing functions (in the Script Modules section).
function clearVars() {
    for x in "$@"; do unset `echo $x`; done
}


################################################################
##################  Script Modules/Functions  ##################
################################################################

# Choose the first name server returned from a DIG NS and use it for all future queries.
# TODO: add a name-server tester to avoid delays in future lookups.
function getNameServers() {
    NAME_SERVER=$(dig ns ${DEFAULT_OPTIONS} +short ${DOMAIN} | head -1)
    # Check to ensure that name-server exists and is a valid host. If not, fall back to GoogleDNS.
    [[ -z "$NAME_SERVER" || -z `host ${NAME_SERVER} | grep -Pv '(NXDOMAIN)|not found'` ]] && NAME_SERVER="8.8.8.8"
    printf "${TC_BLUE}Primary Nameserver${TC_NORMAL}: "
    [[ "${NAME_SERVER}" == "8.8.8.8" ]] \
        && echo "NONE (defaulting to ${TC_BOLD}8.8.8.8${TC_NORMAL} Google Public DNS)" || echo "${NAME_SERVER}"
}

# Get the SPF record(s) for the domain.
## Keeping the "grep" below without a "head/tail" operation or pipe,
## to tell the user of the script if there are multiple SPF records.
function getSPF() {
    SPF_RECORD=$(dig txt ${DEFAULT_OPTIONS} +short ${DOMAIN} @${NAME_SERVER})
    (checkFallbackLookup "$SPF_RECORD") || SPF_RECORD=$(fallbackLookup "${DOMAIN}" "txt" "1.1.1.1")
    SPF_RECORD=$(echo "${SPF_RECORD}" | grep -i "v=spf1")
    [ -z "$SPF_RECORD" ] && SPF_RECORD="NONE"
    echo "${TC_CYAN}SPF Record${TC_NORMAL}: ${SPF_RECORD}"
}

# Get the DMARC record for the domain.
## Nothing really special here.
function getDMARC() {
    DMARC_RECORD=$(dig txt ${DEFAULT_OPTIONS} +short _dmarc.${DOMAIN} @${NAME_SERVER} | head -1 | sed 's/\\//g')
    [ -z "$DMARC_RECORD" ] && DMARC_RECORD="NONE"
    (checkFallbackLookup "$DMARC_RECORD") || DMARC_RECORD=$(fallbackLookup "_dmarc.${DOMAIN}" "txt" "1.1.1.1")
    echo "${TC_RED}DMARC Record${TC_NORMAL}: ${DMARC_RECORD}"
}

# Get the MX record(s) for the domain.
function getMX() {
    MX_RECORDS=$(dig mx ${DEFAULT_OPTIONS} +short ${DOMAIN} @${NAME_SERVER})
    (checkFallbackLookup "$MX_RECORDS") || MX_RECORDS=$(fallbackLookup "$DOMAIN" "mx" "1.1.1.1")
    MX_RECORDS=$(echo "$MX_RECORDS" | sed -r 's/^(\s|\t)*/\t/g' | tr '\n' ' ')
    # Check to see if the MX_RECORDS variable contains ANYTHING but spaces/tabs/newlines...
    # If it doesn't break out before continuing the function.
    [[ -z "`echo "${MX_RECORDS}" | grep -Pim1 '[a-z0-9\.-]'`" ]] \
        && MX_RECORD_OUT="NONE" && echo -e "${TC_GREEN}MX Record(s)${TC_NORMAL}: NONE\n" && return
    MX_RECORD_OUT=
    for hostname in $MX_RECORDS; do
        if [[ -n `echo "$hostname" | grep -Poi '^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}\.?$'` \
        || "$hostname" =~ '^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}\.?$' ]]; then
            # It's an FQDN. The dig should be done against a public DNS since the FQDN can be for a different domain.
            hostname="${hostname} \t(Resolved IP: `dig a +short ${hostname} @8.8.8.8 | head -1`)\n"
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
    echo -e "${TC_GREEN}MX Record(s)${TC_NORMAL}:\n${MX_RECORD_OUT}\n"
}

# Run an RBL check against the web-server/A-record IP of the domain.
## TODO: consider changing "host" command to a dig instead.
function RBL_getALookup() {
    # Begin RBL Check
    echo "Attempting A-record RBL check..."
    A_RECORD=$(host ${DOMAIN} | grep -v 'IPv6' | head -n1 | awk '{print $4}')
    if [[ -z "${A_RECORD}" || "${A_RECORD}" =~ [a-zA-Z0-9\-] ]]; then
        echo "DNS A-Record for ${DOMAIN} isn't defined..."
    else
        printf "Checking Barracuda RBL for the web server IP address (${A_RECORD})... "
        lookupIP "${A_RECORD}"
    fi
    echo
}

# Run an RBL check against all resolved IPs from the MX record entries.
## TODO: consider changing "host" command to a dig instead.
function RBL_getMXLookup() {
    [[ "${MX_RECORD_OUT}" == "NONE" ]] && return
    # RBL Check on Mail Servers in MX records.
    echo "Attempting MX-record RBL check..."
    for i in $(host $DOMAIN | grep -Po 'mail is handled by \d+ (.*)$' | grep -Poi '([a-z0-9\-]+\.)+' | tr '\n' ' '); do
        if [[ ! i =~ '^(\d+\.){3}\d+\.?$' ]]; then
            A_RECORD=$(host $i | grep -v 'IPv6' | head -n1 | awk '{print $4}')
        else A_RECORD="$i"; fi
        printf "Checking Barracuda RBL for the mail server IP address (${A_RECORD})... "
        lookupIP "${A_RECORD}"
    done
    echo
}

# Run an IP against the BRBL. Maybe add more RBL options later.
function lookupIP () {
    # Reverse the IP address to prepare it for the DNS record query.
    local BRBL_LOOKUP=
    for i in {4..1}; do local BRBL_LOOKUP="${BRBL_LOOKUP}`echo "${1}" | cut -d'.' -f${i}`."; done
    local BRBL_LOOKUP="${BRBL_LOOKUP}b.barracudacentral.org"
    # Running this query against a public DNS service.
    local IS_LISTED=$(dig a +short ${BRBL_LOOKUP} @1.1.1.1)
    if [ -n "$IS_LISTED" ]; then echo "[${TC_RED}LISTED${TC_NORMAL}]"; else echo "[${TC_GREEN}NOT LISTED${TC_NORMAL}]"; fi
}

# Check a public DNS server if the chosen Name Server fails or times out on a lookup.
# ARGS:
#    $1 = Variable of previous DNS lookup.
function checkFallbackLookup() {
    [[ "$1" =~ (timed out|unreachable|NXDOMAIN|not found) ]] && return 1 || return 0
}
# Actually do the lookup if the above check returns anything but 0.
# ARGS:
#    $1 = Record to look up.
#    $2 = Record type (MX, TXT, etc).
#    $3 = Target (public) DNS server.
function fallbackLookup() {
    # Give this DNS lookup a bit more grace with time/tries.
    local FBLKUP=$(dig +time=5 +tries=3 +short "$2" "$1" @${3})
    if [[ "${FBLKUP}" =~ (timed out|unreachable|NXDOMAIN|not found) ]] || [ -z "${FBLKUP}" ]; then
        echo "NONE"
    else echo "${FBLKUP}"; fi
}



################################################################
################################################################

# Two-liner to run the main function.
quickDNS_main "$@"
exit 0
