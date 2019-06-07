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
    # Unset some variables.
    clearVars "DOMAINS MX_IP_LIST NO_COLORS V4_LOOKUP V6_LOOKUP SKIP_GET_DOMAIN PTR_RECORD FULL_IP REVERSED_IP"

    [[ "${1:0:2}" == "-R" || "${1:0:2}" == "-r" ]] \
        && SKIP_GET_DOMAIN="YES"
    # The first arg to the program must be a QUOTED list of space-separated domains to check.
    if [ -z "${SKIP_GET_DOMAIN}" ]; then
        if [[ -z "$1" || -z `echo "${1}" | grep -Poi '^([a-z0-9\.\-]+\.[a-z]{2,})(\s+[a-z0-9\.\-]+\.[a-z]{2,})*'` ]]; then
            usage
        else
            DOMAINS="${1}"
            # Remove this from the lineup of arguments, to check any options below.
            shift
        fi
    fi

    # DEFAULT_OPTIONS: Default options for the timeout on the 'dig' lookups that aren't fallback lookups.
    DEFAULT_OPTIONS="+time=2 +tries=2 +short"

    # Interpret arguments to the program.
    while getopts dnR:r: opts; do
        case $opts in
            n) NO_COLORS="YES" ;;
            r) [[ -n "${V6_LOOKUP}" || -n "${DOMAINS}" ]] \
                && echo "You must use the -r flag with a valid IPv4 address, and without any domains." && usage
                V4_LOOKUP="${OPTARG}" ;;
            R) [[ -n "${V4_LOOKUP}" || -n "${DOMAINS}" ]] \
                && echo "You must use the -R flag with a valid IPv6 address, and without any domains." && usage
                V6_LOOKUP="${OPTARG}" ;;
            d) set -x ;;
            #:) echo "Option -${OPTARG} requires an argument." >&2 ;;
            *) usage ;;
        esac
    done

    # Terminal color setup and dependency check.
    colors "${NO_COLORS}"
    depCheck "dig host grep awk sed tr printf cut head tac"

    # Run RBL Lookup function if -r or -R flag was present.
    # Validation happens inside function call
    if [[ -n "${V4_LOOKUP}" || -n "${V6_LOOKUP}" ]]; then
        # The below will work because only one of the two can be defined anyway.
        RBL_CHECK_ADDR="${V4_LOOKUP}${V6_LOOKUP}"
        echo "Checking RBLs for IP address: ${TC_PURPLE}${RBL_CHECK_ADDR}${TC_NORMAL}"
        getPTR "${RBL_CHECK_ADDR}"
        checkAllRBLs "${RBL_CHECK_ADDR}"
        echo && exit 0
    fi

    # Begin the main loop.
    for fqdn in ${DOMAINS[@]}; do
        # Run the script for a domain. Start by resetting variables and then crunching the DNS.
        clearVars "NAME_SERVER SPF_RECORD DMARC_RECORD MX_RECORD_OUT MX_RECORDS A_RECORD MX_IP_LIST PTR_RECORD FULL_IP REVERSED_IP"
        DOMAIN="${fqdn}"
        printBanner "${fqdn}"

        getNameServers
        getSPF
        getDMARC
        getMX
        RBL_CHECKED_IPS=
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
    echo "USAGE: $0 \"domain.name [domain.two domain.three ... domain.n]\" [OPTIONS]"
    echo "-- OR -- $0 {-r ipv4-addr | -R ipv6-addr}"
    echo
    echo " Get information about 'domain.name' such as SPF, MX records,"
    echo "  associated IPs, DMARC, RBL stats, and other email-related info."
    echo " Alternatively, do an RBL lookup against the given IP address."
    echo
    echo "OPTIONS:"
    echo "    -n    Don't use any colors."
    echo "    -d    Put the script into debug mode. BEWARE, this will generate"
    echo "           significantly more output as a step-by-step for the script."
    echo "    -r    Check the given IPv4 address against a list of popular DNSBLs."
    echo "    -R    Same as above but with IPv6 addresses (EXPERIMENTAL,TENTATIVE)."
    echo
    echo "NOTES:"
    echo " - Multiple space-separated domains can be passed to this script"
    echo " -- but the list must be double-quoted."
    echo " - You can only check ONE IP ADDRESS at a time with the -R or -r flags."
    exit 1
}

# ARGS
#   $1 The domain name or IP adress used to print the banner
function printBanner() {
    echo "################################################################################"
    echo "Checking DNS information for ${TC_BOLD}${TC_YELLOW}${1}${TC_NORMAL}..."
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
        TC_PURPLE=`tput setaf 5 2>/dev/null`
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
    NAME_SERVER=$(dig ns ${DEFAULT_OPTIONS} ${DOMAIN} | head -1)
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
    SPF_RECORD=$(dig txt ${DEFAULT_OPTIONS} ${DOMAIN} @${NAME_SERVER})
    (checkFallbackLookup "$SPF_RECORD") || SPF_RECORD=$(fallbackLookup "${DOMAIN}" "txt" "1.1.1.1")
    SPF_RECORD=$(echo "${SPF_RECORD}" | grep -i "v=spf1")
    [ -z "$SPF_RECORD" ] && SPF_RECORD="NONE"
    if [[ $(echo ${SPF_RECORD} | wc -l) -gt 1 ]]; then
        echo "${TC_CYAN}WARNING${TC_NORMAL}: Multiple SPF Records Found! There should only be 1 SPF Record per domain."
        SPF_RECORD=$(echo ${SPF_RECORD} | tr '\n' ';' | sed 's,;$,,')
        oldIFS=${IFS} && IFS=';' read -ra SPF_RECORD <<< ${SPF_RECORD}
        for i in "${!SPF_RECORD[@]}"; do
            echo -e "${TC_CYAN}SPF Record ($((${i}+1)))${TC_NORMAL}:\t${SPF_RECORD[${i}]}"
        done
        IFS=${oldIFS}
    else 
        echo -e "${TC_CYAN}SPF Record${TC_NORMAL}:\t${SPF_RECORD}"
    fi
}

# Get the DMARC record for the domain.
## Nothing really special here.
function getDMARC() {
    DMARC_RECORD=$(dig txt ${DEFAULT_OPTIONS} _dmarc.${DOMAIN} @${NAME_SERVER} | head -1 | sed 's/\\//g')
    [ -z "$DMARC_RECORD" ] && DMARC_RECORD="NONE"
    (checkFallbackLookup "$DMARC_RECORD") || DMARC_RECORD=$(fallbackLookup "_dmarc.${DOMAIN}" "txt" "1.1.1.1")
    echo "${TC_RED}DMARC Record${TC_NORMAL}: ${DMARC_RECORD}"
}

# Get the A record for the domain
function getA() {
    echo "`dig ${DEFAULT_OPTIONS} a ${1} | tail -n1`"
}

# Get the MX record(s) for the domain.
function getMX() {
    MX_RECORDS=$(dig mx ${DEFAULT_OPTIONS} ${DOMAIN} @${NAME_SERVER})
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
            local MX_IP=$(dig a ${DEFAULT_OPTIONS} ${hostname} @8.8.8.8 | head -n1)
            MX_IP_LIST="${MX_IP_LIST} ${MX_IP}"
            hostname="${hostname} \t(Resolved IP: ${MX_IP})\n"
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

# Check PTR record for an IPv4 Address
# ARGS:
#   $1 = IP Address to lookup
function getPTR() {
    # validate IPv4 address
    local IP4_PATTERN='^((1\d{2}|2[0-4]\d|25[0-5]|\d{1,2})\.){3}(1\d{2}|2[0-4]\d|25[0-5]|\d{1,2})$'
    if [[ -n `echo "${1}" | grep -Poi "${IP4_PATTERN}"` ]]; then
        # reverse IP address and append '.in-addr.arpa' and store separately to filter result
        local REVERSED_IP=$(printf %s "${1}." | tac -s.)in-addr.arpa
        # perform lookup and filter result
        PTR_RECORD=$(dig ${DEFAULT_OPTIONS} ptr "${REVERSED_IP}" | tail -n1)
        # test ANSWER to see if it is equal to "PTR" - if so, then there is no PTR found against this ip4 address
        [ -z "${PTR_RECORD}" ] && PTR_RECORD="not defined"
    else # Not an IPv4 Address - check to see if it is IPv6
        ip_validation ${1}
        [[ $? -ne 0 ]] && echo "Invalid IP Address" && usage
        build_groups_array ${1}
        expand_address
        PTR_RECORD=$(dig ${DEFAULT_OPTIONS} ptr "${REVERSED_IP}" | tail -n1)
        # test ANSWER to see if it is equal to "PTR" - if so, then there is no PTR found against this ip6 address
        [ -z "${PTR_RECORD}" ] && PTR_RECORD="not defined"
    fi

}

# Run an RBL check against the web-server/A-record IP of the domain.
function RBL_getALookup() {
    # Begin RBL Check
    # set the A_RECORD variable
    A_RECORD=$(getA ${DOMAIN})

    if [[ -z "${A_RECORD}" || \
        -z `echo "${A_RECORD}" | grep -Poi '^((1\d{2}|2[0-4]\d|25[0-5]|\d{1,2})\.){3}(1\d{2}|2[0-4]\d|25[0-5]|\d{1,2})$'` ]]; then
        echo "DNS A-Record for ${DOMAIN} isn't defined; skipping A-record RBL check..."
    else
        # As long as the IP hasn't already been checked by RBLs, proceed.
        ## Otherwise, skip with a notification.
        echo "Attempting A-record RBL check for ${A_RECORD}..."
        getPTR ${A_RECORD}
        echo "  --========--   ${TC_BOLD}${TC_PURPLE}${A_RECORD}${TC_NORMAL} (PTR: ${PTR_RECORD})    --========--  "
        if [[ -z `echo "${RBL_CHECKED_IPS}" | grep -Poi "${A_RECORD}"` ]]; then
            lookupIP "${A_RECORD}" "b.barracudacentral.org" "Barracuda RBL"
            RBL_CHECKED_IPS="${RBL_CHECKED_IPS} ${A_RECORD}"
        else echo "IP ${A_RECORD} has already been checked. Skipping."; fi
    fi
    echo

}

# Run an RBL check against all resolved IPs from the MX record entries.
function RBL_getMXLookup() {
    [[ "${MX_RECORD_OUT}" == "NONE" || -z "${MX_IP_LIST}" ]] && return
    # RBL Check on Mail Servers in MX records.
    echo "Attempting MX-record RBL check..."
    # So much simpler and cleaner, without performing more unnecessary DNS lookups.
    for i in ${MX_IP_LIST[@]}; do checkAllRBLs "${i}"; done
    echo
}

# Check against all available DNSBL locations for this script.
# ARGS:
#    $1 = Target IP Address
function checkAllRBLs() {
    # Extract the PTR record from the IP address. If not defined, default.
    getPTR ${1}
    [ -z "${PTR_RECORD}" ] && PTR_RECORD="not defined"
    # Start the output of the RBL checks.
    echo "  --========--   ${TC_BOLD}${TC_PURPLE}${1}${TC_NORMAL} (PTR: ${PTR_RECORD})    --========--  "
    [[ -n `echo "${RBL_CHECKED_IPS}" | grep -Poi "${1}"` ]] \
        && echo "IP ${1} has already been checked. Skipping." && return 1
    lookupIP "${1}" "b.barracudacentral.org" "Barracuda RBL"
    lookupIP "${1}" "spam.dnsbl.sorbs.net" "SORBS Spam"
    lookupIP "${1}" "dnsbl-1.uceprotect.net" "UCEPROTECTL1"
    lookupIP "${1}" "bl.spamcop.net" "SpamCop"
    lookupIP "${1}" "noptr.spamrats.com" "SpamRats NoPTR (no-PTR-record spammers)"
    lookupIP "${1}" "dyna.spamrats.com" "SpamRats DYNA (suspicious PTR records)"
    lookupIP "${1}" "rbl.megarbl.net" "MegaRBL"
    lookupIP "${1}" "zen.spamhaus.org" "Spamhaus ZEN"
    lookupIP "${1}" "dnsbl.spfbl.net" "SPFBL"
    lookupIP "${1}" "ubl.unsubscore.com" "LASHBACK"
    lookupIP "${1}" "db.wpbl.info" "WPBL"
    lookupIP "${1}" "cbl.abuseat.org" "Composite Blocking List (CBL)"
    RBL_CHECKED_IPS="${RBL_CHECKED_IPS} ${1}"
    return 0
}

# Run an IP against the given RBL.
# ARGS:
#    $1 = Target IP address,
#    $2 = DNSBL location,
#    $3 = (optional) RBL name.
function lookupIP () {
    # Reverse the IP address to prepare it for the DNS record query.
    local BRBL_LOOKUP=
    for i in {4..1}; do local BRBL_LOOKUP="${BRBL_LOOKUP}`echo "${1}" | cut -d'.' -f${i}`."; done
    local BRBL_LOOKUP="${BRBL_LOOKUP}${2}"
    # Running this query against a public DNS service.
    local IS_LISTED=$(dig a ${DEFAULT_OPTIONS} ${BRBL_LOOKUP} @8.8.8.8)
    local CHECKING_INDICATOR=
    local CHECKING_RESULT=
    [ -n "$3" ] && local CHECKING_INDICATOR="Checking \"${TC_BOLD}${3}${TC_NORMAL}\" " \
        || local CHECKING_INDICATOR="Checking DNSBL at \"${TC_BOLD}${2}${TC_NORMAL}\" "
    if [ -n "$IS_LISTED" ]; then
        local CHECKING_RESULT="[${TC_RED}LISTED${TC_NORMAL}]"
        local LISTED_REASON=$(dig txt ${DEFAULT_OPTIONS} ${BRBL_LOOKUP} @8.8.8.8)
        local CHECKING_RESULT=`echo -e "${CHECKING_RESULT}\n ----> Given Reason (if any): ${LISTED_REASON}"`
    else local CHECKING_RESULT="[${TC_GREEN}NOT LISTED${TC_NORMAL}]"; fi

    printf "%-65s : %s\n" "${CHECKING_INDICATOR}" "${CHECKING_RESULT}"
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
    local FBLKUP=$(dig +time=5 +tries=3 +short "${2}" "${1}" @${3})
    if [[ "${FBLKUP}" =~ (timed out|unreachable|NXDOMAIN|not found) ]] || [ -z "${FBLKUP}" ]; then
        echo "NONE"
    else echo "${FBLKUP}"; fi
}
################################################################
######################  IPv6 Functions  ########################
################################################################

# Counts the number of groups given in the ipv6 address
# ARGS:
#   $1 = IPv6 Address.
count_groups() {
    local groups=$(echo ${1} | tr ':' ' ' | wc -w)
    # ensure there are no more than 8 groups
    [[ ${groups} -gt 8 ]] && echo "Too Many Groups Detected" && return 1
    [[ ${groups} -lt 1 ]] && echo "Not Enough Groups Detected" && return 1
    # set global group count var and return
    GROUP_COUNT=${groups}
    return 0
}

# Checks the validity of the given IPv6 Address
# Only Base 16 digits and {:|::} are allowed
# ARGS:
#   $1 = IPv6 Address
ip_validation() {
    [[ ! ${1} =~ ^[0-9a-fA-F\:]+$ || ${1} =~ [\:]{3} || $(echo ${1} | grep "::" -o | wc -l) -gt 1 ]] \
        && return 1
    # group count 
    count_groups ${1}
    [[ $? -ne 0 ]] && return 1
    return 0
}

# Sets the value of ZERO_START to be the start of the zeros
# Sets the value of ZERO_END to be the end of the zeros
# ARGS:
#   $1 = IPv6 Address
find_zeros() {
    # group count = 8 indicates that there is no :: in the address
    if [[ ${GROUP_COUNT} -ne 8 ]]; then
        # find location of :: and save in ZERO_START variable
        for ((i=0; i < 8; i += 1)); do
            local group=$(echo ${1} | cut -d: -f$((${i}+1)))
            # this line performs the array front-load
            GROUPS_ARRAY[${i}]=${group}
            # ZERO_START is the first group that reads as an empty string, ZERO_END = (MAX_GROUPS - GROUP_COUNT + ZERO_START)
            [[ ${group} == "" ]] && ZERO_START=$((${i})) && ZERO_END=$((8-${GROUP_COUNT}+${ZERO_START})) && return 0
        done
    fi
}

# ARGS:
#   $1 = IPv6 Address
build_groups_array() {
    find_zeros ${1}
    local offset=-1 # offset is used to offset cut fields after zeros have been written to the array
    # fill an indexed array with the groups
    for ((i=0; i < 8; i += 1)); do
        if [[ (${i} -ge ${ZERO_START} && ${i} -lt ${ZERO_END}) ]]; then
            GROUPS_ARRAY[${i}]='0000'
            ((offset++))
            continue
        fi
        # fill an indexed array with the groups
        if [[ ${offset} -eq -1 ]]; then
            local group=$(echo ${1} | cut -d: -f$((${i}+1)))
        else 
            local group=$(echo ${1} | cut -d: -f$((${i}+1-${offset})))
        fi
        GROUPS_ARRAY[${i}]=${group}
    done
    # test for ::nnnn (edge case)
    [[ ${1} =~ ^::[0-9a-fA-F]{1,4}$ && ${i} -eq 8 ]] && GROUPS_ARRAY[7]=$(echo ${1} | cut -d: -f3)
    # rewrite elements to be 4 chars long each
    for ((i=0; i < 8; i += 1)); do
        expand_group ${GROUPS_ARRAY[${i}]} ${i}
    done
}

# Expands an IPv6 group to 4 digits
# ARGS:
#   $1 = group
#   $2 = group array index
expand_group() {
    local zeros_to_add=$((4-$(echo -n ${1} | wc -m)))
    for ((n=0; n < ${zeros_to_add}; n += 1)); do
        local new_group="${new_group}0"
    done
    local new_group="${new_group}${1}"
    GROUPS_ARRAY[${2}]=${new_group}
}

# Expands and delimits an IPv6 Address, then reverses it to be used for PTR lookups
expand_address() {
    delimit_address
    reverse_address
}
 
# Reverses an expanded and delimited IPv6 Address and append .ip6.arpa.
reverse_address() {
    REVERSED_IP=$(echo "$(echo ${FULL_IP} | tac -s. | sed 's,.$,,').ip6.arpa." | tr -d '\n')
}

# Delimits an expanded IPv6 Address with '.'
delimit_address() {
    FULL_IP=
    # iterate over the array and concatenate each element into one string
    for ((i=0; i < 8; i += 1)); do
        FULL_IP="${FULL_IP}${GROUPS_ARRAY[${i}]}"
    done
    # add . between each digit
    FULL_IP=$(echo ${FULL_IP} | sed 's,.,&.,g')
}

################################################################
################################################################
################################################################
################################################################
# main function.
quickDNS_main "$@"
exit 0