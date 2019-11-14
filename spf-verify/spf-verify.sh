#!/bin/bash

# SPF-VERIFY.sh
# Description: Verify if a raw email file would pass SPF for the sending MAIL-FROM domain.
# Contributors:
#   Notsoano Nimus <postmaster@thestraightpath.email>
# Repo: https://github.com/NotsoanoNimus/email-security-toolkit/tree/master/spf-verify
# Date [of first use]: 21 May, 2019
# Reference: RFC 7208
###########

# Script Return Code Index:
# 0 - Successful validation (SPF PASS)
# 1 - Neutral action (SPF check hit a neutral mechanism). Something like:
### -- ?all, or ?a:thisisneutral.com, or ?ip4:1.1.1.1
# 2 - SoftFail action (SPF check hit a softfail mechanism). Same as above but ~ instead of ?.
# 3 - HardFail action (SPF check hit a hardfail mechanism). Same as neutral but - instead.
# 255 - NONE Result: Either the SPF record wasn't found for the sending domain, or
### -- the sending domain is blank/indeterminate (usually indicating a DSN/NDR/Notification).


######################################################################################
# spf-verify is a script to verify if a sending IP address for an email passes SPF checks
#  based on the information in the given email file. It is also useful to display lookups
#  and detailed information about a domain's SPF record.
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

# Include common functions.
source ../common/common.sh


# main function
function SPFVerify_main() {
    # If the EMAIL_SECURITY_COMMON import isn't defined, then the common functions are not available. Exit!
    [ -z "${EMAIL_SECURITY_COMMON}" ] && echo "The script could not import the required common library, and therefore could not run. Aborting." && exit 1
    # Immediately set up the trap for the cleanup function on exit.
    trap cleanup EXIT
    # Set up the environment with a clean slate, and verify passed arguments.
    initialize "$@"

    # Branch off the email headers into their own file to avoid collisions with headers on FW'd emails.
    getEmailHeaders

    # Attempt to find the SMTP MAIL FROM domain. Placed into SPF_DOMAIN variable.
    findEnvFromDomain
    # This line is needed as a failsafe to cut Carriage Returns.
    ### Not certain yet why carriage returns were being appended to the SPF_DOMAIN variable.
    ### TODO: Investigate this.
    SPF_DOMAIN=$(echo "${SPF_DOMAIN}" | sed -r 's/\x0d//g')

    # See if the returned domain-name was "NULL". Act accordingly.
    [[ "${SPF_DOMAIN}" == "NULL" ]] \
        && echo "Envelope-From is blank or couldn't be found, implying this email is likely a notification email. Result is NONE. Nothing to do..." \
        && exit 255
    # Check to see if this script was called from the DMARC script.
    ### If so, it will have the "--get-domain" option. Return the domain and exit.
    [ "$2" == "--get-domain" ] && echo "${SPF_DOMAIN}" && exit 1
    echo "${TC_BOLD}${TC_YELLOW}Envelope-From Domain${TC_NORMAL}: ${SPF_DOMAIN}"

    # Do a TXT lookup on the SPF_DOMAIN to get a look at SPF.
    getSPFRecord "${SPF_DOMAIN}"
    echo "${TC_BOLD}${TC_CYAN}SPF Record${TC_NORMAL}: ${SPF_RECORD}"

    # Attempt to extract identifying information on the source IP address.
    ### NOTE: When getting the IP, it will affect how later lookups are done based on the type (IPv4/6).
    ##### For example, if an IPv6 address is detected, per the RFC, all "a:" mechanisms are actually
    ##### queries against AAAA record types instead.
}

# usage
# -- Display general usage and help for the script.
function usage() {
    echo "USAGE: $0 email-file [OPTIONS]"
    echo "  Verify the SPF fail-type/pass status of a raw email based on either the"
    echo "  originating IP (default) or via a check of Received-header IP addresses."
    echo
    echo "OPTIONS:"
    echo "  -r domain      Look for the sending IP address stamped in the Received"
    echo "                  header that is a hop TO the given FQDN. See example below."
    echo "                  This option is very useful in cases where the IP address"
    echo "                  cannot be determined from a 'source-IP' type header AND if"
    echo "                  the email has gone through more hops (such as through LMTP)."
    echo "  -v             Be verbose in output about the SPF action, and about the"
    echo "                  particulars of the domain's SPF record."
    echo "  -n             Do not use colors in the output for the script."
    echo && exit 1
}

# cleanup
# -- Clean up any temporary files with a trap.
function cleanup() {
    rm -f ${RAW_HEADERS}
}

# initialize
# -- Set up the script environment. Mainly used to ensure dependencies are installed.
function initialize() {
    # Initialize/Blank some variables as needed.
    SPF_DOMAIN=; SPF_RECORD=; EMAIL_FILE=; VERBOSE=; NO_COLORS=;
    ALL_RX_HEADERS=; SPECIFIC_RX_MTA=;
    RAW_HEADERS="/tmp/spf-verify-$$"
    touch ${RAW_HEADERS}

    # Test given parameters...
    [[ -z "$1" || "$1" =~ ^--?h(elp)?$ ]] && usage
    [ ! -f "$1" ] && echo "ERROR: $0: Please provide a valid file!" && exit 1
    EMAIL_FILE="$1"
    # Shift the filename parameter out of the way to process the OPTIONS field, if any.
    shift
    unix2dos --quiet ${EMAIL_FILE} 2>&1 >/dev/null

    # Only get the params for later if this is NOT a call to just get the SPF domain.
    [[ -z `echo "$*" | grep -Poi '\-\-get\-domain'` ]] && \
    while getopts vnrd: opts; do
        case $opts in
            v) VERBOSE="YES" ;;
            n) NO_COLORS="YES" ;;
            r) ALL_RX_HEADERS="YES" ;;
            d) SPECIFIC_RX_MTA="${OPTARG}" ;;
            *) usage ;;
        esac
    done

    # Initialize colors.
    colors "${NO_COLORS}"
}

# getEmailHeaders
# -- Extract only the headers we're working with, to prevent headers from forwarded emails
# ---- from interfering with our SPF investigation.
function getEmailHeaders() {
    cat ${EMAIL_FILE} | \
    while read -r line || [[ -n "${line}" ]]; do
        # Echo is used here rather than printf so it doesn't break...
        local TEMPVAR=$(echo "${line}" | xxd -ps)
        # --- If the line is just a CRLF then it's a blank line, begin BODY section.
        [[ "${TEMPVAR}" == "0d0a" ]] && break \
            || echo "${line}" >>${RAW_HEADERS}
    done
}

# findEnvFromDomain
# -- Place the SMTP Envelope-From address into the SPF_DOMAIN variable.
# ---- This can be done through various ways, so all of them are exhausted before giving up.
# THIS WILL NEED WORK OVER TIME.
function findEnvFromDomain() {
    # Try the Return-Path header...
    local RET_PATH=$(grep -Poi '^Return-Path:.*?$' ${RAW_HEADERS} | head -n1)
    if [ -n "${RET_PATH}" ]; then
        local RET_PATH=$(echo "${RET_PATH}" | sed -r 's/Return-Path:\s*|[<>]//g' | sed -r 's/.*?\@//')
        [ -z "${RET_PATH}" ] && local RET_PATH="NULL"
        SPF_DOMAIN="${RET_PATH}"
        return
    fi
    # Try the 'envelope-from' token that some MTAs stamp onto Received headers.
    local ENVFROM_RX=$(grep -Poi '^Received:.*?envelope-from.*?$' ${RAW_HEADERS})
    if [ -n "${ENVFROM_RX}" ]; then
        # Try to rip it apart piecewise.
        local ENVFROM_RX=$(echo "${ENVFROM_RX}" | sed -r 's/^Received:.*?envelope-from\s*//i' \
            | grep -Poi '[a-z0-9_\.\-\+=%$]+\@[a-z0-9\.\-]+\.[a-z0-9\-_\+]{2,}' | head -n1 \
            | sed -r 's/.*?\@//')
        SPF_DOMAIN="${ENVFROM_RX}"
        return
    fi
    # Try the 'envelope-from' token that's sometimes in the "Received-SPF" header from MTAs.
    local ENVFROM_RX_SPF=$(grep -Poi '^Received-SPF:.*?$' ${RAW_HEADERS} | head -n1)
    if [ -n "${ENVFROM_RX_SPF}" ]; then
        # Again, rip it apart piecewise.
        local ENVFROM_RX_SPF=$(echo "${ENVFROM_RX_SPF}" | sed -r 's/^Received-SPF:.*?envelope-from(\s*|=)//gi' \
            | grep -Poi '[a-z0-9_\.\-\+=%$]+\@[a-z0-9\.\-]+\.[a-z0-9\-_\+]{2,}' | head -n1 \
            | sed -r 's/.*?\@//')
        SPF_DOMAIN="${ENVFROM_RX_SPF}"
        return
    fi

    # If the checks fail, fail out.
    SPF_DOMAIN="NULL"
}

# getSPFRecord
# -- A quick function to get the SPF record from the Env-From domain's DNS.
function getSPFRecord() {
    local QUERY_STR="$1"
    SPF_RECORD=$(dig txt +short ${QUERY_STR} | grep -Pi '^"?v=spf1')
    if [ -z "${SPF_RECORD}" ]; then
        # Retry the SPF query against a public DNS server.
        SPF_RECORD=$(dig txt +short ${QUERY_STR} @1.1.1.1 | grep -Pi '^"?v=spf1')
        [ -z "${SPF_RECORD}" ] \
            && outputError "The domain ${TC_CYAN}${SPF_DOMAIN}${TC_NORMAL} does not have a valid SPF record." 3
    fi

    # Check for multiple SPF records. If so, warn the user and continue using the first one.
    [[ `echo "${SPF_RECORD}" | grep -Poi '^"?v=spf1' | wc -l` -gt 1 ]] \
        && echo "${TC_RED}WARNING${TC_NORMAL}: This domain has multiple SPF records!" \
        && echo -e "\tThis script will use the first received SPF record, as many MTAs will do," \
        && echo -e "\tbut this should be fixed for an accurate result." \
        && SPF_RECORD=$(echo "${SPF_RECORD}" | grep -m1 -Pi '^"?v=spf1')

    # Sanitize the record.
    SPF_RECORD=$(echo "${SPF_RECORD}" | sed -r 's/^"|"$//g')
}



#########################################################
#########################################################
#########################################################
#########################################################
# Run the main function and exit cleanly.
SPFVerify_main "$@"
exit 0
