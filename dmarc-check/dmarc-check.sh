#!/bin/bash

# DMARC-CHECK.sh
# Description: Verify if a raw email file would pass DMARC. Seek and output any errors.
# Contributors:
#   Notsoano Nimus <postmaster@thestraightpath.email>
# Repo: https://github.com/NotsoanoNimus/email-security-toolkit/tree/master/dmarc-check
# Date [of first use]: 15 May, 2019
# Reference: RFC 7489
##############


######################################################################################
# dmarc-check is a script to verify if an email file would pass DMARC.
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

# Import common functions.
source ../common/common.sh


# main function
function DMARCcheck_main() {
    # Immediately set up the trap for the cleanup function on exit.
    trap cleanup EXIT
    # Set up the environment with a clean slate, and verify passed arguments.
    initialize "$@"

    # Get the domain segment in the From header.
    getDMARCDomain
    # Check for a DMARC record.
    getDMARCRecord "${DMARC_DOMAIN}"
    # Parse the record and ensure it includes all necessary tags per RFC 7489.
    parseDMARCRecord

    # Display DMARC information to the user.
    outputDMARCInfo

    echo

    # Return codes for alignment checks:
    ## 0 = PASS and ALIGNMENT.
    ## 1 = PASS and MISALIGNMENT.
    ## 2 = FAIL and ALIGNMENT.
    ## 3 = FAIL and MISALIGNMENT.
    # DMARC will need at least one '0' return-code to be validated successfully.

    # Check SPF.
    #SPF_ALIGN=$(checkSPFAlignment)
    # Check DKIM. Sets the DKIM_ALIGN variable.
    checkDKIMAlignment

    # Output the result of DMARC on the message.
    printAlignment
}



# usage
# -- Display general usage and help for the script.
function usage() {
    echo "USAGE: $0 email-file [OPTIONS]"
    echo "  Verify the DMARC pass/fail status of a raw email and explain"
    echo "  the action taken as specified by the DMARC record."
    echo
    echo "OPTIONS:"
    echo "  -v             Be verbose in output about the DMARC record, and about"
    echo "                  the particulars of the email's alignment."
    echo "  -a             Include outputs from both the DKIM and SPF verification."
    echo "  -d             Show DKIM verification output."
    echo "  -s             Show SPF verification output."
    echo "  -n             Do not use colors in the output for the script."
    echo
    echo "NOTES:"
    echo "  This script depends on \"dkim-verify.sh\", another script designed"
    echo "   to validate DKIM-Signature headers, and \"spf-verify.sh\" to verify"
    echo "   SPF sender authentication."
    echo
    echo "  These can be predefined in two variables respectively with \"export\":"
    echo "    DKIM_VERIFY and SPF_VERIFY"
    echo "  Otherwise the script will search for the scripts in the same directory."
    echo "  And lastly, in two directories: ../dkim-verify/ and ../spf-verify/,"
    echo "   which correspond to the structure of the email-security-toolkit project."
    echo && exit 1
}

# cleanup
# -- Clean up any temporary files with a trap. This may not be needed but is scaffolding.
function cleanup() {
    :
}

# initialize
# -- Set up the script environment. Mainly used to ensure dependencies are installed.
function initialize() {
    # Initialize/Blank some variables as needed.
    EMAIL_FILE=; VERBOSE=; NO_COLORS=;
    SHOW_DKIM=; SHOW_SPF=;
    PASS_ALIGN=0; PASS_NOALIGN=1; FAIL_ALIGN=2; FAIL_NOALIGN=3
    # Set these to FAIL/MISALIGNMENT by default.
    SPF_ALIGN=3; DKIM_ALIGN=3

    # Test given parameters...
    [[ -z "$1" || -n `echo "$1" | grep -Poi '^--?h(elp)?$'` ]] && usage
    [ ! -f "$1" ] && echo "ERROR: $0: Please provide a valid file!" && exit 1
    EMAIL_FILE="$1"
    # Shift the filename parameter out of the way to process the OPTIONS field, if any.
    shift

    while getopts vnads opts; do
        case $opts in
            v) VERBOSE="YES" ;;
            n) NO_COLORS="YES" ;;
            a) SHOW_DKIM="YES" && SHOW_SPF="YES" ;;
            d) SHOW_DKIM="YES" ;;
            s) SHOW_SPF="YES" ;;
            *) usage ;;
        esac
    done

    # Initialize colors.
    colors "${NO_COLORS}"

    # This array needs to be defined after the colors are defined.
    PRINT_ALIGN=( \
        "${TC_GREEN}PASS${TC_NORMAL} and ${TC_GREEN}ALIGNMENT${TC_NORMAL}" \
        "${TC_GREEN}PASS${TC_NORMAL} and ${TC_RED}MISALIGNMENT${TC_NORMAL}" \
        "${TC_RED}FAIL${TC_NORMAL} and ${TC_YELLOW}ALIGNMENT${TC_NORMAL}" \
        "${TC_RED}FAIL${TC_NORMAL} and ${TC_RED}MISALIGNMENT${TC_NORMAL}" \
    )
    # For our greatest verbosities.
    PRINT_ALIGN_EXTRA=( \
        "the authentication method passed and the domain name aligns with the ASPF/ADKIM policy" \
        "the authentication method passed but the domain name doesn't align with the ASPF/ADKIM policy" \
        "the authentication method failed despite the domain name alignment with the ASPF/ADKIM policy" \
        "the authentication method failed and the domain name doesn't align with the ASPF/ADKIM policy"
    )

    # Check to ensure dkim-verify.sh and spf-verify.sh are available.
    if [[ -n "${DKIM_VERIFY}" && -n "${SPF_VERIFY}" ]]; then
        if ! [[ -f "${DKIM_VERIFY}" && -f "${SPF_VERIFY}" ]]; then
            echo "ERROR: $0: SPF_VERIFY and DKIM_VERIFY are predefined, but are not valid files!"
            echo "  Either move the scripts to `dirname $0` (the directory of this script) or"
            echo "  define the variables correctly."
            exit 255
        fi
    else
        # This will actually alternatively check for the two scripts within the structure
        ## presented by the entire 'email-security-toolkit' project.
        if [[ -f "./dkim-verify.sh" && -f "./spf-verify.sh" ]]; then
            DKIM_VERIFY="./dkim-verify.sh"; SPF_VERIFY="./spf-verify.sh"
        elif [[ -f "../dkim-verify/dkim-verify.sh" && -f "../spf-verify/spf-verify.sh" ]]; then
            DKIM_VERIFY="../dkim-verify/dkim-verify.sh"; SPF_VERIFY="../spf-verify/spf-verify.sh"
        else
            echo "ERROR: $0: SPF_VERIFY and DKIM_VERIFY are not defined, and both needed scripts"
            echo "  are not in `dirname $0` (the directory of this script). The above variables"
            echo "  must either be defined to point to spf-verify.sh and dkim-verify.sh, or those"
            echo "  two script names must be in the mentioned directory."
            exit 255
        fi
    fi
}

# printNeatly
# -- Sub-function for neat printing.
# PARAMS: 1 - Left column, 2 - Separator, 3 - Right column, 4 - Spread (spaces apart)
function printNeatly() {
    printf "%-${4}s ${2} %s\n" "${1}" "${3}"
}

# getField
# -- Extract the value from the given tag.
# PARAMS: 1 = tag name
function getField() {
    local RETVAL=$(echo "${DMARC_RECORD}" | grep -Poi '\b'"$1"'=.*?(;|$)' | sed -r 's/;.*//g' | head -n1)
    echo "${RETVAL:`expr ${#1} + 1`:${#RETVAL}}"
}

# getDMARCDomain
# -- Use the top-most Header-From field to get the target DMARC domain.
function getDMARCDomain() {
    # Grep out the top-most From header, and grab the domain after the @ symbol.
    DMARC_DOMAIN=$(grep -Poi '^From:.*?$' ${EMAIL_FILE} | head -n1 | sed -r 's/.*?\@([0-9a-z\.\-]+[a-z]{2,})>?\s*$/\1/gi')
    [ -z "${DMARC_DOMAIN}" ] && outputError "The top-most \"From\" header doesn't have a valid FQDN." 2
}

# getDMARCRecord
# -- Obtain and parse the DMARC TXT record from public DNS.
function getDMARCRecord() {
    local QUERY_STR="_dmarc.$1"
    DMARC_RECORD=$(dig txt +short ${QUERY_STR})
    if [ -z "${DMARC_RECORD}" ]; then
        # Retry the query against a public DNS.
        DMARC_RECORD=$(dig txt +short ${QUERY_STR} @1.1.1.1)
        [ -z "${DMARC_RECORD}" ] \
            && outputError "The domain ${TC_CYAN}${DMARC_DOMAIN}${TC_NORMAL} does not have a valid DMARC record." 3
    fi
    # Clean up the record:
    DMARC_RECORD=$(echo "${DMARC_RECORD}" | tr -d '\n' | sed -r 's/\\|\s+|\t+|\"//g')
}

# parseDMARCRecord
# -- Verify that the DMARC record includes tags required by RFC 7489.
function parseDMARCRecord() {
    # According to the RFC, the "v" tag must be the first value, is case-sensitive, and must equal "DMARC1".
    [[ -z `echo "${DMARC_RECORD}" | grep -Po '^v=DMARC1'` ]] \
        && outputError "DMARC Record doesn't include a proper \"version\" tag (v=DMARC1)." 4
    DMARC_VERSION=$(getField "v")
    [[ ! "${DMARC_VERSION}" == "DMARC1" ]] \
        && outputError "DMARC Record doesn't include a proper \"version\" tag (v=DMARC1)." 4

    # The next mandatory field is the "p" tag.
    DMARC_ACTION=$(getField "p")
    [[ -z `echo "${DMARC_ACTION}" | grep -Poi '^(none|reject|quarantine)$'` ]] \
        && outputError "DMARC Record doesn't include a proper action in the \"p\" tag (none, reject, or quarantine)." 6

    # "sp" tag: OPTIONAL; subdomain action.
    DMARC_SUB_ACTION=$(getField "sp")
    DMARC_SUB_ACTION_DISPLAY="${DMARC_SUB_ACTION}"
    # Assumes that "sp" is defined.
    DMARC_SUB_DEFINED="YES"
    # If not defined, default to the same policy as the "p" tag.
    [ -z "${DMARC_SUB_ACTION}" ] \
        && DMARC_SUB_ACTION_DISPLAY="${DMARC_ACTION} (not defined; defaulted to \"p\" tag action)" \
        && DMARC_SUB_ACTION="${DMARC_ACTION}" \
        && DMARC_SUB_DEFINED="NO"
    # If "sp" is defined and for some reason doesn't have a valid action, warn the user and default to "p" value anyway.
    [[ -z `echo "${DMARC_SUB_ACTION}" | grep -Poi '^(none|reject|quarantine)'` ]] \
        && outputInfo "DMARC Record doesn't include a proper action in the \"sp\" tag (none, reject, or quarantine)." \
        && DMARC_SUB_ACTION_DISPLAY="${DMARC_ACTION} (bad value; defaulted to \"p\" tag action)" \
        && DMARC_SUB_ACTION="${DMARC_ACTION}" \
        && DMARC_SUB_DEFINED="NO"

    # "pct" tag: OPTIONAL; defaults to 100.
    DMARC_PCT=$(getField "pct")
    DMARC_PCT_DISPLAY="${DMARC_PCT}"
    [ -z "${DMARC_PCT}" ] && DMARC_PCT_DISPLAY="100 (default)" && DMARC_PCT="100"
    # Verify that it only consists of 1-3 numbers (1-100).
    [[ -z `echo "${DMARC_PCT}" | grep -Poi '^([0-9]{1,2}|100)$'` ]] \
        && DMARC_PCT_DISPLAY="100 (default; bad definition within record)" && DMARC_PCT="100"

    # "adkim" tag: OPTIONAL; defaults to "r" (relaxed)
    # In strict mode the sender domain name must exactly match the corresponding d=name (in the DKIM mail headers).
    ### In relaxed mode any subdomain of d=domain (in the mail headers) will also be accepted. Thus if d=example.com
    ### in the mail header then mail from user@example.com will pass from either adkim = r or adkim=s, however, mail
    ### from user@a.example.com will fail if adkim=s but pass if adkim=r.
    DMARC_ADKIM=$(getField "adkim")
    [[ -z `echo "${DMARC_ADKIM}" | grep -Po '^[rs]$'` ]] && DMARC_ADKIM="r"

    # "aspf" tag: OPTIONAL; defaults to "r" (relaxed)
    # In strict mode the domain.name in the MAIL FROM command (in SMTP) and the from: header (in the mail item) must
    ### match exactly. In relaxed mode any valid subdomain of domain.name is acceptable.
    DMARC_ASPF=$(getField "aspf")
    [[ -z `echo "${DMARC_ASPF}" | grep -Po '^[rs]$' ` ]] && DMARC_ASPF="r"

    # "fo" tag: OPTIONAL; defaults to "0".
    # Defines the error reporting policy the sending MTA requests from the receiving MTA. Multiple options may be defined
    ### using colon (:) separated values, for example, fo=0:s
    DMARC_FO=$(getField "fo")
    [[ -z "${DMARC_FO}" || -z `echo "${DMARC_FO}" | grep -Poi '^[01ds]((:[01ds]){1,3})?$'` ]] && DMARC_FO="0"

    # "rf" tag: OPTIONAL; defaults to "afrf".
    # Defines the reporting format the sending MTA requests from the receiving MTA.
    DMARC_RF=$(getField "rf")
    [[ -z "${DMARC_RF}" || -z `echo "${DMARC_RF}" | grep -Po '^(afrf|iodef)$'` ]] && DMARC_RF="afrf"

    # "ri" tag: OPTIONAL: defaults to "86400".
    # Defines the reporting interval in seconds. receivimg MTAs must be able to send daily (86400) reports and should be
    ### able to send hourly (3600) reports but on a best efforts basis. Implicitly anything less than 1 hour (3600) can be
    ### rounded up to 1 hour by the receiving MTA.
    DMARC_RI=$(getField "ri")
    if [[ -z "${DMARC_RI}" || -z `echo "${DMARC_RI}" | grep -Po '^[0-9]{4,9}$'` ]]; then
        DMARC_RI="86400 (defaulted to daily)"
    else if [[ ${DMARC_RI} -le 3600 ]]; then DMARC_RI="3600 (rounded up)"; fi; fi

    # "rua" tag: OPTIONAL: defaults to not sending any aggregate reports if an address isn't defined.
    DMARC_RUA=$(getField "rua")
    ## It's not that important, no need to validate this. Just check whether or not it exist, and strip off mailto: URI objects.
    [[ -z "${DMARC_RUA}" ]] \
        && DMARC_RUA="Not defined, aggregate report emails will not be sent from receiving MTAs." \
        || DMARC_RUA=$(echo "${DMARC_RUA}" | sed 's/mailto://g')

    # "ruf" tag: OPTIONAL; defaults to not sending anything if not defined.
    DMARC_RUF=$(getField "ruf")
    [[ -z "${DMARC_RUF}" ]] \
        && DMARC_RUF="Not defined, detailed failure-report emails will not be sent from receiving MTAs." \
        || DMARC_RUF=$(echo "${DMARC_RUF}" | sed 's/mailto://g')
}

# outputDMARCInfo
# -- Generate a clean report describing how the DMARC record works.
function outputDMARCInfo() {
    local SPACING="30"
    echo "${TC_PURPLE}${TC_BOLD}Extracted Header-From Domain${TC_NORMAL}: ${DMARC_DOMAIN}"
    echo "${TC_CYAN}${TC_BOLD}DMARC Record${TC_NORMAL}: ${DMARC_RECORD}"
    #printf "%-65s : %s \n" "Policy:" "${DMARC_ACTION}"
    printNeatly "Policy" ":" "${DMARC_ACTION}" "${SPACING}"
    printNeatly "Subdomain Policy" ":" "${DMARC_SUB_ACTION_DISPLAY}" "${SPACING}"
    printNeatly "Percentage affected" ":" "${DMARC_PCT_DISPLAY}" "${SPACING}"
    printf "DKIM Classification (ADKIM)    : "
    [[ "${DMARC_ADKIM}" == "s" ]] \
        && echo 's (strict mode; DKIM-Signature d= tag CANNOT be a subdomain of the header-from domain)' \
        || echo 'r (relaxed mode; default; DKIM-Signature d= tag CAN be a subdomain of the header-from domain)'
    printf "SPF Classification (ASPF)      : "
    [[ "${DMARC_ASPF}" == "s" ]] \
        && echo 's (strict mode; Envelope-From CANNOT be a subdomain of the header-from domain)' \
        || echo 'r (relaxed mode; default; Envelope-From CAN be a subdomain of the header-from domain)'
    # Cutoff goes here for verbosity. Everything else below requires a 'v' flag to output.
    [ -z "${VERBOSE}" ] && return
    printNeatly "Reporting Policy" ":" "${DMARC_FO}" "${SPACING}"
        echo -e "\t0 - (DEFAULT) Generate report to the sending MTA if all underlying checks failed."
        echo -e "\t1 - Generate a report to the sending MTA if any underlying check failed."
        echo -e "\td - Generate a report if DKIM checks fail."
        echo -e "\ts - Generate a report if SPF checks fail."
    printNeatly "Reporting Format" ":" "${DMARC_RF}" "${SPACING}"
    printNeatly "Reporting Interval" ":" "${DMARC_RI}" "${SPACING}"
    printNeatly "Mail Reports Address (RUA)" ":" "${DMARC_RUA}" "${SPACING}"
    printNeatly "Failure Reports Address (RUF)" ":" "${DMARC_RUF}" "${SPACING}"
}

# checkDKIMAlignment
# -- Check the alignment and pass state for the DKIM half of DMARC.
## The result of this depends on two things:
## (1) the retcode from dkim-verify; (2) the domain in the d tag
function checkDKIMAlignment() {
    # If dkim-verify returns a 0 code, the DKIM-Signature is valid.
    if [ -z "${SHOW_DKIM}" ]; then
        ${DKIM_VERIFY} ${EMAIL_FILE} 2>&1 >/dev/null
    else
        echo "${TC_BOLD}=============== RUNNING DKIM CHECK${TC_NORMAL}:"
        [ -z "${NO_COLORS}" ] \
            && ${DKIM_VERIFY} ${EMAIL_FILE} \
            || ${DKIM_VERIFY} ${EMAIL_FILE} -n
        echo
    fi
    local RETCODE=$?
    local RETDOMAIN=$(${DKIM_VERIFY} ${EMAIL_FILE} --get-domain)

    local VERDICT=0
    # Check strict mode "s" for an exact domain match in the DKIM d= tag and the header-from.
    # Or, check relaxed mode "r" for the d= tag to be a subdomain of the header-from domain.
    if [[ "${DMARC_ADKIM}" == "s" && "${RETDOMAIN}" == "${DMARC_DOMAIN}" ]] || \
        [[ "${DMARC_ADKIM}" == "r" \
        && -n `echo "${RETDOMAIN}" | grep -Poi "${DMARC_DOMAIN}"'$'` ]]; then local VERDICT=${PASS_ALIGN};
    else local VERDICT=${PASS_NOALIGN}; fi
    # If the DKIM verification failed, add 2 to the VERDICT variable.
    [[ ${RETCODE} -ne 0 ]] && local VERDICT=$(expr ${VERDICT} + 2)

    DKIM_ALIGN=${VERDICT}
}

# checkSPFAlignment
# -- Check the alignment and pass state for the SPF half of DMARC.
## The result of this depends on two things:
## (1) the retcode from spf-verify; (2) the envelope-from domain of the email.
## SPECIAL NOTE:
### DMARC specifically uses the MAIL FROM SPF check (rather than the EHLO/HELO check).
### -- RFC 7489, section 4.1
function checkSPFAlignment() {
    # If spf-verify returns a 0 code, the SPF check for the email passed.
    # PASSING is the only qualifier that will work for DMARC. The result CANNOT be neutral/softfail.
    if [ -z "${SHOW_SPF}" ]; then
        ${SPF_VERIFY} ${EMAIL_FILE} 2>&1 >/dev/null
    else
        echo "${TC_BOLD}=============== RUNNING SPF CHECK${TC_NORMAL}:"
        [ -z "${NO_COLORS}" ] \
            && ${SPF_VERIFY} ${EMAIL_FILE} \
            || ${SPF_VERIFY} ${EMAIL_FILE} -n
        echo
    fi
    local RETCODE=$?
    local RETDOMAIN=$(${SPF_VERIFY} ${EMAIL_FILE} --get-domain)

    local VERDICT=0
    # Check strict mode "s" for an exact domain match in the SMTP MAIL-FROM and the header-from.
    # Or, check relaxed mode "r" for the SMTP MAIL-FROM to be a subdomain of the header-from domain.
    if [[ "${DMARC_ASPF}" == "s" && "${RETDOMAIN}" == "${DMARC_DOMAIN}" ]] || \
        [[ "${DMARC_ASPF}" == "r" \
        && -z `echo "${RETDOMAIN}" | grep -Poi "${DMARC_DOMAIN}"'$'` ]]; then local VERDICT=${PASS_ALIGN};
    else local VERDICT=${PASS_NOALIGN}; fi
    # If the SPF verification failed, add 2 to the VERDICT variable.
    [[ ${RETCODE} -ne 0 ]] && local VERDICT=$(expr ${VERDICT} + 2)

    SPF_ALIGN=${VERDICT}
}

# printAlignment
# -- Print the results of each alignment, as well as the PASS/FAIL state.
function printAlignment() {
    printf "DKIM  :   ${PRINT_ALIGN[${DKIM_ALIGN}]}"
    [ -n "${VERBOSE}" ] && echo " (${PRINT_ALIGN_EXTRA[${DKIM_ALIGN}]})" || echo
    printf "SPF   :   ${PRINT_ALIGN[${SPF_ALIGN}]}"
    [ -n "${VERBOSE}" ] && echo " (${PRINT_ALIGN_EXTRA[${SPF_ALIGN}]})" || echo
    printf "DMARC :   "

    if [[ ${DKIM_ALIGN} -eq 0 || ${SPF_ALIGN} -eq 0 ]]; then
        echo "${TC_GREEN}${TC_BOLD}PASS${TC_NORMAL}"
        outputInfo "There was at least one PASS-and-ALIGNMENT, so DMARC passes."
    else
        echo "${TC_RED}${TC_BOLD}FAIL${TC_NORMAL}"
        outputInfo "DMARC will need at least one PASS-and-ALIGNMENT to pass."
        # Let the user know what receiving MTAs will do with FAIL emails.
        local ACTION_INFO="Based on the DMARC policy, receiving MTAs that are checking for DMARC will"
        if [[ ${DMARC_ACTION} == "reject" || ${DMARC_ACTION} == "quarantine" ]]; then
            local ACTION_INFO="${ACTION_INFO} ${DMARC_ACTION} "
            [[ "${DMARC_SUB_DEFINED}" == "YES" ]] && ! [[ "${DMARC_SUB_ACTION}" == "${DMARC_ACTION}" ]] \
                && local ACTION_INFO="${ACTION_INFO}(${DMARC_SUB_ACTION} for subdomains) "
        else ACTION_INFO="${ACTION_INFO} not doing anything to "; fi
        local ACTION_INFO="${ACTION_INFO}${DMARC_PCT}% of failed emails as they are checked."

        [ -n "${VERBOSE}" ] && [[ -n "${DMARC_RUA}" || -n "${DMARC_RUF}" ]] \
            && outputInfo "Aggregate and Failure reports are generated for these failures respectively to the RUA and RUF addresses above, as defined."
        # Speak it
        outputInfo "${ACTION_INFO}"
    fi
    echo
}



#########################################################
#########################################################
#########################################################
#########################################################
# Run the main function and exit cleanly.
DMARCcheck_main "$@"
exit 0
