#!/bin/bash

# DKIM-VERIFY.sh
# Description: Validate and verify a raw email DKIM signature. Seek and output any errors.
# Contributors:
#   Notsoano Nimus <postmaster@thestraightpath.email>
# Repo: https://github.com/NotsoanoNimus/email-security-toolkit/tree/master/dkim-verify
# Date [of first use]: 17 March, 2019
# Reference: RFC 6376
################


######################################################################################
# dkim-verify is a script to verify and troubleshoot a raw email's most recent DKIM-
#   Signature header, in accordance with RFC 6376.
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


# usage
# -- Display general usage and help for the script.
function usage() {
    echo "USAGE: $0 email-file [OPTIONS]"
    echo "  Verify the validity of the most recent DKIM-Signature header"
    echo "  on a raw email message, and if there are errors, output them."
    echo
    echo "OPTIONS:"
    echo "    -n              Do not use colors in the output."
    echo "    --get-domain    Used to get the domain from the signature."
    echo
    echo "NOTES:"
    echo " + The '--get-domain' parameter is typically used by the DMARC"
    echo " -- script when checking for alignment, but can be used manually."
    echo " + Since the nature of this script involves hashing algorithms,"
    echo " -- very slight changes in a copy/paste of an email could result"
    echo " -- in the script reporting a failed hash. To prevent this, it's"
    echo " -- best to use the original email file, if possible."
    echo && exit 1
}

# DKIMVerify_main
# -- Main function for the script, where all of the processing is done.
function DKIMVerify_main() {
    # ===== SETUP =====
    # Immediately set up the trap for the cleanup function on exit.
    trap cleanup EXIT
    # Check if the second argument to the script is '--get-domain'.
    #  'getDomain' returns the domain from the 'd=' tag in the signature.
    #  As indicated, it is called from the DMARC module to check for domain alignment.
    if [[ "$2" == "--get-domain" ]]; then
        getDomain "$@"
    fi
    # Set up the script environment.
    initialize "$@"
    #################################################

    # ===== SIGNATURE EXTRACTION =====
    # Extract the DKIM Signature from the message, and double-check that one has been extracted without issue.
    echo " +++ Extracting DKIM-Signature from the message..."
    extractSignature "${EMAIL_FILE}"
    [ $? -eq 1 ] && outputError "${TC_RED}PERMFAIL${TC_NORMAL}: Failed to find a DKIM-Signature header." 2
    #################################################

    # ===== PUBLIC KEY / DNS =====
    # Get the selector (s=) field and the domain (d=) field.
    echo " +++ Acquiring the public RSA key used to sign the header."
    DKIM_SELECTOR=$(getField "s" "${DKIM_SIGNATURE}")
    DKIM_DOMAIN=$(getField "d" "${DKIM_SIGNATURE}")
    # Get the public key from DNS using the extracted information.
    VALID_PUBKEY=0
    getPubkey "${DKIM_SELECTOR}" "${DKIM_DOMAIN}" 2>&1 >/dev/null
    # Check the retcode from the 'getPubkey' function to output possible errors, if any.
    PUBKEY_RETCODE=$?
    [ "${PUBKEY_RETCODE}" -ne 0 ] && parsePubkeyRetcode "${PUBKEY_RETCODE}"
    outputResult "Public Key Valid" "+" "${VALID_PUBKEY}"
    #################################################

    # ===== DIVISION / PARSING =====
    # Split up the email into headers vs. body.
    getEmailSections
    #################################################

    # ===== CANONICALIZATION =====
    echo " +++ Getting the canonicalization types and performing canonicalization..."
    # Get the canonicalization types (simple/relaxed) from the 'c=' field.
    getSigCanon
    # Set up the CANON_HEADERS and CANON_BODY variables.
    #  These are the CANONICALIZED version of the headers and body, respectively.
    canonicalizeHeader
    canonicalizeBody
    # SANITY CHECK: Check that both canonicalizations are set.
    if [[ -z "${CANON_BODY}" || -z "${CANON_HEADERS}" ]]; then
        outputError "${TC_RED}PERMFAIL${TC_NORMAL}: Could not canonicalize the message. Reason unknown." 4
    fi
    outputResult "Headers & Body Canonicalized" "+" 0
    #################################################

    # ===== BODY HASH (EXTRACTION, CALCULATION, & RESULTS) =====
    echo " +++ Interpreting and verifying the Body Hash (bh) field of the signature..."
    # Get the body-hash field from the signature.
    DKIM_BODYHASH=$(getField "bh" "${DKIM_SIGNATURE}")
    # Calculate the body hash locally from the CANON_BODY value.
    #  This function sets the CALC_BODY_HASH variable.
    calcBodyHash
    # Output their values to the terminal.
    outputInfo "Extracted Body Hash:  ${TC_YELLOW}${DKIM_BODYHASH}${TC_NORMAL}" "+"
    outputInfo "Calculated Body Hash: ${TC_YELLOW}${CALC_BODY_HASH}${TC_NORMAL}" "+"
    # Compare the two strings for a match and output the result to the terminal.
    # -- RFC standard is to PERMFAIL if the Body Hash doesn't verify, because the Body Hash is used in the next step.
    if [[ "${DKIM_BODYHASH}" == "${CALC_BODY_HASH}" ]]; then
        outputResult "Body Hash Match" "+" 0
    else
        outputError "${TC_RED}PERMFAIL${TC_NORMAL}: The Body Hash did not verify successfully. Signature is not valid!" 5
    fi
    #################################################

    # ===== HEADER HASH (EXTRACTION, DECRYPTION, CALCULATION, & RESULTS) =====
    echo " +++ Verifying primary DKIM signature (b) with the public key..."
    # Extract the encrypted header-hash field from the signature.
    DKIM_HEADER_SIGNATURE=$(getField "b" "${DKIM_SIGNATURE}")
    # Define a temporary file as a place to temporarily store information.
    TEMP_OUT="/tmp/dkim-verify-$$"
    # Decode the Base64 signature and store it into the temporary file.
    echo "${DKIM_HEADER_SIGNATURE}" | base64 -di >$TEMP_OUT 2>/dev/null
    if [ $? -ne 0 ]; then
        # If, for whatever reason, the 'b=' tag contains bad Base64, error out.
        outputError "${TC_RED}PERMAIL${TC_NORMAL}: Bad Base64 in the \"b\" tag of the DKIM-Signature header." 16
    fi
    outputInfo "Base64 decoded." "+"
    # Multipart step:
    # - Decrypt the hash with OpenSSL's RSA utility, suppressing STDERR.
    # - Get the final two lines, cut at the '-' symbols and get fields 2&3.
    # - Use sed to: (1) delete occurrences of 2+ spaces and the content following it, (2) remove spaces and dashes.
    # - Delete all newline characters to aggregate the hexdump into one string.
    DKIM_HEADER_HASH=$(openssl rsautl -inkey ${PUBKEY_FILE} -pubin -in ${TEMP_OUT} -asn1parse 2>/dev/null \
      | tail -2 | cut -d'-' -f2,3 \
      | sed -r 's/\s{2,}.*?$//g' | sed -r 's/(\s|-)//g' | tr -d '\n')
    if [[ "${DKIM_HEADER_HASH}" =~ '[^0-9a-zA-Z]' || -z "${DKIM_HEADER_HASH}" ]]; then
        outputError "${TC_RED}PERMFAIL${TC_NORMAL}: Could not decrypt or decipher the header hash value from the \"b\" tag." 15
    fi
    outputInfo "Header hash decrypted successfully." "+"
    echo " +++ Calculating header hash locally..."
    # Calculate the header hash locally (from the CANON_HEADERS value).
    #  This function sets the CALC_HEADER_HASH variable.
    calcHeaderHash
    # Display the results of each computation.
    outputInfo "Extracted Header Hash:  ${TC_CYAN}${DKIM_HEADER_HASH}${TC_NORMAL}" "+"
    outputInfo "Calculated Header Hash: ${TC_CYAN}${CALC_HEADER_HASH}${TC_NORMAL}" "+"
    # Compare the two strings for a match and output the result to the terminal.
    # -- RFC standard is to PERMFAIL if the Hash doesn't verify; it's the primary signature.
    if [[ "${DKIM_HEADER_HASH}" == "${CALC_HEADER_HASH}" ]]; then
        outputResult "Header Hash Match" "+" 0
    else
        outputError "${TC_RED}PERMFAIL${TC_NORMAL}: The Header Hash did not verify successfully. Signature is not valid!" 5
    fi
    #################################################

    # ===== THAT'S ALL, FOLKS =====
    echo " +++ [${TC_BOLD}${TC_GREEN}SUCCESS${TC_NORMAL}] DKIM Signature is ${TC_GREEN}${TC_BOLD}VALID${TC_NORMAL}!"
    #################################################
}



# cleanup
# -- Clean up any temporary files with a trap.
function cleanup() {
    rm -f /tmp/dkim-verify-$$*
    [ -f /tmp/dkim-verify-email-$$ ] && rm -f /tmp/dkim-verify-email-$$
}

# initialize
# -- Set up the script environment. Mainly used to ensure dependencies are installed.
function initialize() {
    # Initialize/Blank some variables as needed.
    PUBKEY_FILE=/tmp/dkim-verify-$$-pubkey
    DKIM_SIGNATURE=; EMAIL_HEADERS=; EMAIL_BODY=;

    # Test given parameters...
    [[ -z "$1" ]] && usage
    [[ "$1" =~ ^--?h(elp)?$ ]] && usage
    [ ! -f "$1" ] && outputError "Please provide a valid file!" 1
    # Shadow the given email file to the temp file location.
    EMAIL_FILE="/tmp/dkim-verify-email-$$"
    cp "$1" "${EMAIL_FILE}"
    # Shift the filename parameter out of the way to process the OPTIONS field, if any.
    shift
    # Automatically convert LF to CRLF. Saves A LOT of trouble (since DKIM requires CRLF line separation).
    unix2dos --quiet ${EMAIL_FILE} 2>&1 >/dev/null

    # Parse any possible options.
    while getopts n opts; do
        case $opts in
            n) NO_COLORS="YES" ;;
            *) usage ;;
        esac
    done

    # Initialize Colors
    colors "${NO_COLORS}"

    # Check the required dependencies for this script and ensure the system has them available.
    #  All dependencies are defined in the 'common' library, for purposes of centralization and ease of reference.
    checkDependencies "${DKIM_DEPS}"
}

# getDomain
# -- Get the domain from the 'd=' field in the DKIM-Signature, if one is found in the email.
# ---- This is really only used from the DMARC script, but can be called manually if desired.
# PARAMS: Accepts the "all-params" variable "$@" to get command-line arguments to $0.
function getDomain() {
    # Check parameter validity, and shadow the target email accordingly.
    [ ! -f "$1" ] && outputError "Please provide a valid file!" 1
    local EMAIL_FILE="/tmp/dkim-verify-email-$$"
    cp "$1" "${EMAIL_FILE}"
    # Attempt to get the DKIM-Signature header.
    extractSignature "${EMAIL_FILE}" 2>&1 >/dev/null
    local RETURN_DOMAIN=$(getField "d" "${DKIM_SIGNATURE}")
    # A successful population of the RETURN_DOMAIN variable should always return a 254.
    #  Any other return/exit code should be considered a failure to extract a valid domain.
    if [ -n "${RETURN_DOMAIN}" ]; then
        echo "${RETURN_DOMAIN}"
        exit 254
    else exit 1; fi
}

# extractSignature
# -- Extract the top-most DKIM signature from the message. This will comply
# ---- with either 'flat' DKIM signatures or ones broken up into multiple lines.
function extractSignature() {
    # Set DKIM_SIG to the first "DKIM-Signature" header line, and the 15 lines after
    # -- it. Then, preserve the top line (the DKIM-Signature line) and wipe it from
    # -- the variable with a 'sed' command so only that the 15 lines after remain.
    local DKIM_SIG=$(grep -Pi -A15 -m1 '^DKIM-Signature:' "$1")
    echo "${DKIM_SIG}" | grep -Poi '^DKIM-Signature:.*?$' >/tmp/dkim-verify-$$
    local DKIM_SIG=$(echo "${DKIM_SIG}" | sed -r '/^DKIM-Signature:.*?$/d')

    # Preserve the whitespace of the DKIM_SIG variable, echo it into the 'while' loop.
    # -- While there are still lines to read, set TESTVAR to any lines with spaces or
    # -- tabs preceding the content. As soon as TESTVAR doesn't have these, the DKIM
    # -- Signature's indentations have stopped, so we've captured the whole signature.
    IFS=''
    echo "${DKIM_SIG}" | \
    while read -r line || [[ -n "${line}" ]]; do
        local TESTVAR=$(echo "${line}" | grep -Pi '^(\s+|\t+)')
        if [ -n "${TESTVAR}" ]; then echo "${TESTVAR}" >>/tmp/dkim-verify-$$
        else break; fi
    done

    # Cat the constructed temporary file into the DKIM_SIGNATURE variable, then remove the file.
    DKIM_SIGNATURE=$(cat /tmp/dkim-verify-$$)
    rm /tmp/dkim-verify-$$
    # If the signature isn't defined at all, there's nothing to do at all, so quit.
    [ -z "${DKIM_SIGNATURE}" ] && return 1
    # Output the clean version of the Signature, then crunch it before leaving.
    echo "${DKIM_SIGNATURE}" | \
    while read -r line || [[ -n "${line}" ]]; do
        outputInfo "  ${line}" "+"
    done
    DKIM_SIGNATURE_SIMPLE="${DKIM_SIGNATURE}"
    DKIM_SIGNATURE=$(echo "${DKIM_SIGNATURE}" | tr '\n' ' ' | sed -r 's/\s+|\t+//g')
    return 0
}

# getPubkey
# -- Get the Signer's public key using their selector (s=) and their domain (d=).
# PARAMS: 1 = selector, 2 = domain
# RETURN CODES:
#   1 = No DNS TXT record for selector.
#   2 = No Pubkey field in the record.
#   3 = Public key is not a valid key.
function getPubkey() {
    local QUERY_STR="$1._domainkey.$2"
    SIGNER_PUBKEY=$(dig txt +short ${QUERY_STR})
    [ -z "${SIGNER_PUBKEY}" ] && return 1
    SIGNER_PUBKEY=$(echo "${SIGNER_PUBKEY}" | sed -r 's/\\|\s+|\t+|\"//g' | grep -Poi 'p=.*?(;|$)')
    [ -z "${SIGNER_PUBKEY}" ] && return 2

    # All is good! Strip off any possible semi-colons (especially at the end) and rip off the 'p=' via substring.
    SIGNER_PUBKEY=$(echo "${SIGNER_PUBKEY:2:${#SIGNER_PUBKEY}}" | sed -r 's/;//g')

    # Verify that the public key is valid.
    echo "-----BEGIN PUBLIC KEY-----">${PUBKEY_FILE}
    echo "${SIGNER_PUBKEY}">>${PUBKEY_FILE}
    echo "-----END PUBLIC KEY-----">>${PUBKEY_FILE}

    # Use OpenSSL to check for a valid RSA modulus.
    # -- If the return code from OpenSSL is anything but 0, it's not valid.
    openssl rsa -pubin -in ${PUBKEY_FILE} -text -noout 2>&1 >/dev/null
    [ $? -ne 0 ] && return 3

    # Successful return.
    return 0
}

# getEmailSections
# -- Get the header and body sections of the raw email.
function getEmailSections() {
    local HEADERS_PARSED=
    # Read the email line-by-line to begin the splitting process.
    cat $EMAIL_FILE | \
    while read -r line || [[ -n "${line}" ]]; do
        if [ -z "${HEADERS_PARSED}" ]; then
            # Echo is used here rather than printf so it doesn't break...
            local TEMPVAR=$(echo "${line}" | xxd -ps)
            # --- If the line is just a CRLF then it's a blank line, begin BODY section.
            if [[ "${TEMPVAR}" == "0d0a" ]]; then HEADERS_PARSED="TRUE"
            else echo "${line}">>/tmp/dkim-verify-$$; fi
        else
            # When HEADERS_PARSED is set, continue writing the final lines to a separate temp file.
            echo "${line}">>/tmp/dkim-verify-$$-body
        fi
    done
    # Set each variable according to the corresponding capture files, and delete the temp files.
    EMAIL_HEADERS=$(cat /tmp/dkim-verify-$$)
    EMAIL_BODY=$(cat /tmp/dkim-verify-$$-body)
    rm /tmp/dkim-verify-$$ /tmp/dkim-verify-$$-body
}

# parsePubkeyRetcode
# -- Interpret the error code given by fetching the public key from DNS.
function parsePubkeyRetcode() {
    if [ $1 -eq 1 ]; then
        outputError "${TC_RED}TEMPFAIL${TC_NORMAL}: Failed to find DNS TXT record for selector \"${DKIM_SELECTOR}\" at domain \"${DKIM_DOMAIN}\"." 3
    elif [ $1 -eq 2 ]; then
        outputError "${TC_RED}TEMPFAIL${TC_NORMAL}: Found TXT record, but no public key (p=), for selector \"${DKIM_SELECTOR}\" at domain \"${DKIM_DOMAIN}\"." 3
    elif [ $1 -eq 3 ]; then
        outputError "${TC_RED}TEMPFAIL${TC_NORMAL}: Found pubkey in selector record, but it is not a valid RSA key encoded in Base64." 3
    fi
}

# getSigCanon
# -- Get the canonicalization of the DKIM Signature. Set to defaults as necessary.
# -- If no canonicalization algorithm is specified by the Signer, the "simple" algorithm defaults for both header and body.
function getSigCanon() {
    local DKIM_CANON=$(getField "c" "${DKIM_SIGNATURE}")
    if [[ "${DKIM_CANON}" =~ '/' ]]; then
        # Both are explicitly defined, get them.
        DKIM_CANON_HEADER=$(echo "${DKIM_CANON}" | cut -d'/' -f1)
        DKIM_CANON_BODY=$(echo "${DKIM_CANON}" | cut -d'/' -f2)
    elif [ -z "${DKIM_CANON}" ]; then
        # No canon specified, set to defaults (simple/simple).
        DKIM_CANON_HEADER="simple"
        DKIM_CANON_BODY="simple"
    else
        # No slash character, only one specification means that the header canon is explicitly defined. Body is defaulted to "simple".
        DKIM_CANON_HEADER="${DKIM_CANON}"
        DKIM_CANON_BODY="simple"
    fi

    # SANITY CHECK: If anything came out NOT simple or relaxed, set them both to "simple".
    [[ "${DKIM_CANON_HEADER}" != "simple" && "${DKIM_CANON_HEADER}" != "relaxed" ]] && DKIM_CANON_HEADER="simple"
    [[ "${DKIM_CANON_BODY}" != "simple" && "${DKIM_CANON_BODY}" != "relaxed" ]] && DKIM_CANON_BODY="simple"

    outputInfo "Canonicalization Used: ${TC_PURPLE}${DKIM_CANON_HEADER}${TC_NORMAL} (header)/${TC_PURPLE}${DKIM_CANON_BODY}${TC_NORMAL} (body)" "+"
}

# canonicalizeHeader
# -- Canonicalize the header of the email (EMAIL_HEADERS) in accordance with the (DKIM_CANON_HEADER) algorithm.
function canonicalizeHeader() {
    outputInfo "Sanitizing and parsing message header.  " "+"
    CANON_HEADERS=
    if [[ "${DKIM_CANON_HEADER}" == "simple" ]]; then
        # RFC 6376, S 3.4.1:
        # The "simple" header canonicalization algorithm does not change header
        #  fields in any way.  Header fields MUST be presented to the signing or
        #  verification algorithm exactly as they are in the message being
        #  signed or verified.  In particular, header field names MUST NOT be
        #  case folded and whitespace MUST NOT be changed.
        CANON_HEADERS="${EMAIL_HEADERS}"
    elif [[ "${DKIM_CANON_HEADER}" == "relaxed" ]]; then
        # RFC 6376, S 3.4.2:
        # The "relaxed" header canonicalization algorithm MUST apply the following steps in order:
        #  + Convert all header field names (not the header field values) to
        #    lowercase.  For example, convert "SUBJect: AbC" to "subject: AbC".
        local TEMP_OUT=/tmp/dkim-verify-$$
        [ -f "${TEMP_OUT}" ] && rm ${TEMP_OUT}
        echo "${EMAIL_HEADERS}" | \
        while read -r line || [[ -n "${line}" ]]; do
            local HEADER=$(echo "${line}" | cut -d':' -f1 | tr '[:upper:]' '[:lower:]')
            local CUT_TEST=$(echo "${line}" | cut -d':' -f2 | tr '[:upper:]' '[:lower:]')
            if [[ "${HEADER}" == "${CUT_TEST}" || -n `echo "${line}" | grep -Poi '^(\s+|\t+)+.'` ]]; then
                echo -ne "${line}\r\n" >>$TEMP_OUT
                continue
            fi
            LANG='' line=$(echo "${line}" | sed -r 's/^[\x21-\x7E]+://')
            line=$(echo "${HEADER}:${line}" | sed -r 's/\x0a|\x0d//g')
            echo -ne "${line}\r\n" >>$TEMP_OUT
        done
        CANON_HEADERS=$(cat ${TEMP_OUT})
        rm ${TEMP_OUT}

        # Unfold all header field continuation lines as described in
        #  [RFC5322 S 2.2.3]; in particular, lines with terminators embedded in
        #  continued header field values (that is, CRLF sequences followed by
        #  WSP) MUST be interpreted without the CRLF.  Implementations MUST
        #  NOT remove the CRLF at the end of the header field value.
        # -- I'm going to try a slightly different approach to this, rather than intensive scanning.
        echo -n "${CANON_HEADERS}" | xxd -ps | tr '\n' ' ' | tr -d ' ' | sed -r 's/(0d)+/0d/g' | sed -r 's/(0a)+/0a/g' \
          |  sed -r 's/(0[aAdD]){2}((20)+|(09)+)+/20/g' >$TEMP_OUT
        CANON_HEADERS=$(echo -n `cat $TEMP_OUT` | perl -pe 's/([0-9a-fA-F]{2})/chr hex $1/gie')

        # Convert all sequences of one or more WSP characters to a single SP
        #  character.  WSP characters here include those before and after a
        #  line folding boundary.
        #  Delete all WSP characters at the end of each unfolded header field
        #  value.
        CANON_HEADERS=$(echo -n "${CANON_HEADERS}" | sed -r 's/(\s+|\t+)+/ /g')

        # Delete any WSP characters remaining before and after the colon
        #  separating the header field name from the header field value.  The
        #  colon separator MUST be retained.
        # -- Easy, find the first : character, seek and spaces or tabs out and nuke them.
        CANON_HEADERS=$(echo -n "${CANON_HEADERS}" | sed -r 's/(\s|\t)*:(\s|\t)*/:/')

        rm $TEMP_OUT
    else
        # The given canonicalization header doesn't match either above. This shouldn't ever happen.
        outputError "${TC_RED}PERMFAIL${TC_NORMAL}: The canonicalization method for the header (${DKIM_CANON_HEADER}) isn't valid." 255
    fi
}

# canonicalizeBody
# -- Canonicalize the body of the email (EMAIL_BODY) in accordance with the (DKIM_CANON_BODY) algorithm.
function canonicalizeBody() {
    outputInfo "Sanitizing and parsing message body.  " "+"
    CANON_BODY=
    local TEMP_OUT=/tmp/dkim-verify-$$
    if [[ "${DKIM_CANON_BODY}" == "relaxed" ]]; then
        # RFC 6376, S 3.4.4: "relaxed" body canonicalization.
        # Reduce whitespace:
        #  (1) Ignore all whitespace at the end of each line. DO NOT remove the CRLF.
        #  (2) Reduce all sequences of whitespace within a line to a single space character.

        # Here's how the below operation does it:
        # echo EMAIL_BODY (with trailing CRLF) | break the EMAIL_BODY into a hex-dump where each by is a SINGLE column
        # | replace LF w/ space (turns column into a space-separated list of bytes)
        # | replace any consecutive WSP (0x20 & 0x09) w/ a single space.
        # | remove any spaces leading up to a CRLF | mash all terminating CR & LF characters into a single CRLF.
        echo "${EMAIL_BODY}" | xxd -ps -c1 \
          | tr '\n' ' ' | sed -r 's/((20|09)\s+)+/20/g' \
          | sed -r 's/(20\s*)+(0d\s+0a)/0d0a/g' | sed -r 's/(0d\s*0a\s*)+$/0d0a/' | tr -d ' ' >$TEMP_OUT

    else
        # Default to "simple".
        # RFC 6376, S 3.4.3
        # The "simple" body canonicalization algorithm ignores all empty lines
        #  at the end of the message body.  An empty line is a line of zero
        #  length after removal of the line terminator.  If there is no body or
        #  no trailing CRLF on the message body, a CRLF is added.  It makes no
        #  other changes to the message body.  In more formal terms, the
        #  "simple" body canonicalization algorithm converts "*CRLF" at the end
        #  of the body to a single "CRLF".i

        # Operates the same as "relaxed" but isn't crunching whitespace.
        echo "${EMAIL_BODY}" | xxd -c1 -ps | tr -d '\n' | tr -d '\r' >$TEMP_OUT
    fi

    # Translate back from the numerical hex digest to the textual representation.
    CANON_BODY=$(LANG='' echo `cat ${TEMP_OUT}` | perl -pe 's/([0-9a-fA-F]{2})/chr hex $1/gie')
    # Add a trailing CRLF
    CANON_BODY="${CANON_BODY}"`echo -ne "\r\n"`
    rm ${TEMP_OUT}
}

# calcBodyHash
# -- Calculate the body hash from the CANON_BODY variable.
function calcBodyHash() {
    CALC_BODY_HASH=
    local TEMP_OUT=/tmp/dkim-verify-$$
    echo -n "${CANON_BODY}" >$TEMP_OUT

    # Convert the canon. body to hex data, remove all line breaks, swap out repeating \n or \r with \r\n,
    #   ensure final CRLF (\r\n), convert from hex back to ASCII, pipe into the hashing/digest algorithm,
    #   cut out unnecessary particles, convert the hex byte-for-byte to raw binary (ASCII) AGAIN,
    #   replace any possible \r or \n chars, and finally base64-encode the data. Body Hash complete.
    local HASH_PART=$(getField "a" "${DKIM_SIGNATURE}")
    if [[ "${HASH_PART}" =~ 'sha256' ]]; then HASH_ALG="sha256"; else HASH_ALG="sha1"; fi
    echo " +\`---> Hashing Algorithm: ${HASH_PART}"
    # Making a change to this. It should eventually JUST hash, not do anything else.
    # -- Added the OpenSSL hashing function to stop converting back-and-forth with perl.
    CALC_BODY_HASH=$(LANG='' xxd -ps $TEMP_OUT | tr -d '\n' | tr -d '\r' | \
        sed -r 's/(0d)+/0d/g' | sed -r 's/0d\s*$/0d0a/' | \
        perl -pe 's/([0-9a-fA-F]{2})/chr hex $1/gie' | \
        2>/dev/null openssl ${HASH_ALG} -binary | base64)
    rm $TEMP_OUT
}

# calcHeaderHash
# -- Calculate the header hash. Sets the CALC_HEADER_HASH variable.
function calcHeaderHash() {
    # Get the 'h=' field from the signature. This tells the script which order the headers were hashed in.
    #  The 'tr' and 'sed' calls serve to replace ':' and multiple spaces with a single space, respectively.
    DKIM_SIGNED_HEADERS=$(getField "h" "${DKIM_SIGNATURE}" |tr ':' ' ' | sed -r 's/\s+/ /g')
    # Create another testing variable: translate the sanitized signed-headers to lower-case.
    DKIM_SIGNED_HEADERS_TEST=$(echo "${DKIM_SIGNED_HEADERS}" | tr '[:upper:]' '[:lower:]')
    # Make sure the headers contain SOMETHING besides whitespace, and that "from" is included in the signed-headers.
    #  NOTE: The _TEST variable isn't necessary, as ^^ could be used to translate the variable to upper-case. Keeping anyway.
    if [ -z "${DKIM_SIGNED_HEADERS// /}" ]; then
        outputError "${TC_RED}PERMFAIL${TC_NORMAL}: The \"h\" field is empty, there is nothing to sign! This goes against RFC 6367."
    elif ! [[ "${DKIM_SIGNED_HEADERS_TEST}" == *"from"* ]]; then
        outputError "${TC_RED}PERMFAIL${TC_NORMAL}: The \"h\" field does not contain the From header as required by RFC 6367. Signature is not valid!"
    fi
    # Output the headers to a file, cat it into a perl reverse, and store the result into the same temporary file.
    #  This is effectively turning the headers last-first in order (reversing their order).
    local REVERSED_HEADERS_FILE=/tmp/dkim-verify-$$-headers
    echo "${CANON_HEADERS}" >"${REVERSED_HEADERS_FILE}"
    CANON_HEADERS=$(cat $REVERSED_HEADERS_FILE | perl -e 'print reverse <>')
    echo "${CANON_HEADERS}" >"${REVERSED_HEADERS_FILE}"
    # --- MULTIPART SECTION ---
    # --- Scan from oldest header to newest (purpose of the reversal), and once a matching header is found,
    # ---  inject it into the ORDERED_HEADERS_FILE and strip the line out of the REVERSED_HEADERS_FILE.
    # --- ***** No match on a header equals no entry into the final ORDERED_HEADERS_FILE which is used in hash computation.
    # Start by defining a few setup pieces. The pseudo-header "dkim-signaturelast" is appended to the lower-cased, ordered signed-headers.
    DKIM_SIGNED_HEADERS_TEST="${DKIM_SIGNED_HEADERS_TEST} dkim-signaturelast"
    local ORDERED_HEADERS_FILE=/tmp/dkim-verify-$$-ordered-headers
    # Loop through each of the signed-headers, grepping out the FIRST occurrence of the header in the REVERSED file.
    #  In effect, this means that the script is obtaining the OLDEST header of that value FIRST.
    IFS=' '
    for header in ${DKIM_SIGNED_HEADERS_TEST[@]}; do
        # DKIM-Signature analysis comes last. The reason for 'dkim-signaturelast' is part of the RFC standard that states that the FINAL SIGNED HEADER
        #  uses the DKIM-Signature header itself (with the 'b=' tag set to an empty value) in part of the signed computation. This is critical!
        if [[ "${header}" == "dkim-signaturelast" ]]; then
            if [[ "${DKIM_CANON_HEADER}" == "relaxed" ]]; then
                # If the canonicalization is "relaxed", the script can assume that the DKIM-Signature field was already unfolded, so just grab the whole line.
                ADD_N_STRIP=$(grep -Poi '^dkim-signature:.*?$' "${REVERSED_HEADERS_FILE}" | tail -1)
            else
                # Otherwise, we'll need to recursively instruct that the ADD_N_STRIP item be set to the FOLDED version of the DKIM-Signature header,
                #  with an empty 'b=' tag added onto the end.
                # *** IMPORTANT: This is dangerous! It assumes that the "b" field is isolated to its own line and appears as the FIRST value on that folded line!
                # ***** TODO: Consider a fix for this. Though it's not been an issue yet over many tests, it can become an issue easily with "edge" cases.
                # The "indentation character" is whatever whitespace is used to indent the folded DKIM-Signature header when it's multiline.
                local INDENTATION_CHAR=$(echo "${DKIM_SIGNATURE_SIMPLE}" | grep -Poi -m1 '^(\s|\t)+.' | sed -r 's/.$//')
                ADD_N_STRIP=$(echo "${DKIM_SIGNATURE_SIMPLE}" | sed -n '/\bb=/q;p')
                ADD_N_STRIP="${ADD_N_STRIP}\n${INDENTATION_CHAR}b="
            fi
        # When it's not the "dkim-signaturelast" item, simply set ADD_N_STRIP equal to the first line matching the header from the REVERSED_HEADERS_FILE.
        else ADD_N_STRIP=$(grep -Poi -m1 '^'"${header}"':.*?$' "${REVERSED_HEADERS_FILE}"); fi
        # When ADD_N_STRIP is null, simply continue to the next header.
        [ -z "${ADD_N_STRIP}" ] && continue
        # Otherwise, cut the matching line out of the REVERSED_HEADERS_FILE with a sed deletion.
        sed -ri '/^'"${header}"':/d' "${REVERSED_HEADERS_FILE}"
        # If the header starts with 'dkim-signature', then set ADD_N_STRIP equal to the DKIM-Signature field, but WITH THE 'b=' TAG SET TO NULL.
        if [[ "${header}" == "dkim-signature"* ]]; then ADD_N_STRIP=$(echo "${ADD_N_STRIP}" | sed -r 's/\bb=.*?($|;)/b=/'); fi
        # Finally, add ADD_N_STRIP (with a trailing CRLF) to the ORDERED_HEADERS_FILE.
        echo -ne "${ADD_N_STRIP}\r\n" >>"${ORDERED_HEADERS_FILE}"
    done

    # Use sed to kill any empty lines containing only whitespace in the final, ordered headers.
    sed -ri 's/\s+$//g' "${ORDERED_HEADERS_FILE}"
    # Convert all LF to CRLF forcibly.
    unix2dos --quiet "${ORDERED_HEADERS_FILE}" 2>&1 >/dev/null
    # Truncate the end of the file by two bytes, removing any final/trailing CRLF.
    truncate -s -2 "${ORDERED_HEADERS_FILE}"
    # The calculated header hash uses the [algorithm]sum application on the final headers, and the cut is just giving the hash only back from STDOUT.
    CALC_HEADER_HASH=$(`echo ${HASH_ALG}`sum "${ORDERED_HEADERS_FILE}" | cut -d' ' -f1)
    # TEMP FILE removal is done by the TRAP when the script exits - no need to be concerned about cleanup here.
    # ALL DONE! :)
}




################################################################
################################################################
################################################################
################################################################
# main function.
DKIMVerify_main "$@"
exit 0

