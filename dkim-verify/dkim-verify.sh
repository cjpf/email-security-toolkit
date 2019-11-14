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


# main function (scaffolding)
function DKIMVerify_main() {
  :
}

# usage
# -- Display general usage and help for the script.
function usage() {
  echo "USAGE: $0 email-file [OPTIONS]"
  echo "  Verify the validity of the most recent DKIM-Signature header"
  echo "  on a raw email message, and if there are errors, output them."
  echo && exit 1
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

  # Build a space-separated list of dependencies for this script.
  DEPENDENCIES="perl unix2dos openssl base64 dig xxd tr sed sha1sum sha256sum head tail cut truncate"
  # Let the user know
  echo "Checking for necessary dependencies: ${TC_BLUE}${DEPENDENCIES}${TC_NORMAL}"
  # Set the separator/delimiter to ' '
  IFS=' '
  # Iterate through each command above and check for its existence in the $PATH variable using the 'command' command.
  for needed in ${DEPENDENCIES[@]}; do
    command -v $needed 2>&1 >/dev/null
    if [ $? -ne 0 ]; then
      outputError "Missing dependency command \"${needed}\". Please install this on your local machine and try again." 255
    fi
  done
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

# getField
# -- Set the return value to the value of the give variable in the DKIM signature.
# PARAMS: 1 = variable name
# RETURN CODES: "" = non-existent field, "[STRING]" = value of variable
# Example Usage: FIELD_VALUE=$(getField "d")
# ---- Returns the "d=" (domain) value from the DKIM Signature
function getField() {
  # DKIM Signature not defined? Leave with null response.
  [ -z "${DKIM_SIGNATURE}" ] && return 0

  RETVAL=$(echo "${DKIM_SIGNATURE}" | grep -Poi '\b'"$1"'=.*?(;|$)' | sed -r 's/;.*//g' | head -n1)
  echo "${RETVAL:`expr ${#1} + 1`:${#RETVAL}}"
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

# getSigCanon
# -- Get the canonicalization of the DKIM Signature. Set to defaults as necessary.
# -- If no canonicalization algorithm is specified by the Signer, the "simple" algorithm defaults for both header and body.
function getSigCanon() {
  local DKIM_CANON=$(getField "c")
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
}

# canonicalizeHeader
# -- Canonicalize the header of the email (EMAIL_HEADERS) in accordance with the (DKIM_CANON_HEADER) algorithm.
function canonicalizeHeader() {
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

  CANON_BODY=$(LANG='' echo `cat ${TEMP_OUT}` | perl -pe 's/([0-9a-fA-F]{2})/chr hex $1/gie')
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
  local HASH_PART=$(getField "a")
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




#########################################################
#########################################################
#########################################################
#########################################################
# BEGIN MAIN FUNCTION:


# Immediately set up the trap for the cleanup function on exit.
trap cleanup EXIT

# Check if the second argument to the script is '--get-domain'.
# This function just returns the domain from the d= tag.
### This is mostly called from the DMARC script to check for domain alignment.
if [[ "$2" == "--get-domain" ]]; then
    # ... but verification is still needed.
    [ ! -f "$1" ] && outputError "Please provide a valid file!" 1
    cp "$1" "/tmp/dkim-verify-email-$$"
    EMAIL_FILE="/tmp/dkim-verify-email-$$"
    extractSignature "${EMAIL_FILE}" 2>&1 >/dev/null
    RETURN_DOMAIN=$(getField "d")
    echo "${RETURN_DOMAIN}"
    exit 254
fi

# Test given parameters...
[[ "$1" =~ '^--?h(elp)?$' ]] && usage
[ ! -f "$1" ] && outputError "Please provide a valid file!" 1
cp "$1" "/tmp/dkim-verify-email-$$"
EMAIL_FILE="/tmp/dkim-verify-email-$$"
# Shift the filename parameter out of the way to process the OPTIONS field, if any.
shift
unix2dos --quiet ${EMAIL_FILE} 2>&1 >/dev/null

while getopts n opts; do
    case $opts in
        n) NO_COLORS="YES" ;;
        *) usage ;;
    esac
done

# Initialize Colors
colors "${NO_COLORS}"
# Set up the environment with a clean slate (always just in case)
initialize


# Extract the DKIM Signature from the message.
echo " +++ Extracting DKIM-Signature from the message..."
extractSignature "${EMAIL_FILE}"
[ $? -eq 1 ] && outputError "${TC_RED}PERMFAIL${TC_NORMAL}: Failed to find DKIM-Signature header." 2


# Get the selector (s=) field and the domain (d=) field.
echo " +++ Acquiring the public RSA key used to sign the header."
DKIM_SELECTOR=$(getField "s")
DKIM_DOMAIN=$(getField "d")
VALID_PUBKEY=0
getPubkey "${DKIM_SELECTOR}" "${DKIM_DOMAIN}" 2>&1 >/dev/null
# Use the retcode now AND later when using the signature on the canon. headers
PUBKEY_RETCODE=$?
if [ "${PUBKEY_RETCODE}" -eq 1 ]; then
  outputError "${TC_RED}TEMPFAIL${TC_NORMAL}: Failed to find DNS TXT record for selector \"${DKIM_SELECTOR}\" at domain \"${DKIM_DOMAIN}\"." 3
elif [ "$PUBKEY_RETCODE" -eq 2 ]; then
  outputError "${TC_RED}TEMPFAIL${TC_NORMAL}: Found TXT record, but no public key (p=), for selector \"${DKIM_SELECTOR}\" at domain \"${DKIM_DOMAIN}\"." 3
elif [ "$PUBKEY_RETCODE" -eq 3 ]; then
  outputError "${TC_RED}TEMPFAIL${TC_NORMAL}: Found pubkey in selector record, but it is not a valid RSA key encoded in Base64." 3
fi
# This is here like this in case I change the 'if' above AGAIN.
outputResult "Public Key Valid" "+" "${VALID_PUBKEY}"


# Split up the email into headers vs. body.
getEmailSections


# Get the Canonicalization type and canonicalize.
echo " +++ Getting the canonicalization types and performing canonicalization..."
getSigCanon
outputInfo "Canonicalization Used: ${TC_PURPLE}${DKIM_CANON_HEADER}${TC_NORMAL} (header)/${TC_PURPLE}${DKIM_CANON_BODY}${TC_NORMAL} (body)" "+"
# Set up the CANON_HEADERS and CANON_BODY variables.
outputInfo "Sanitizing and parsing message header.  " "+"
canonicalizeHeader
outputInfo "Sanitizing and parsing message body.  " "+"
canonicalizeBody
[[ -z "${CANON_BODY}" || -z "${CANON_HEADERS}" ]] && \
  outputError "${TC_RED}PERMFAIL${TC_NORMAL}: Could not canonicalize the message. Reason unknown." 4
outputResult "Headers & Body Canonicalized" "+" 0


# Interpret the Body Hash.
echo " +++ Interpreting and verifying the Body Hash (bh) field of the signature..."
DKIM_BODYHASH=$(getField "bh")
calcBodyHash
outputInfo "Extracted Body Hash:  ${TC_YELLOW}${DKIM_BODYHASH}${TC_NORMAL}" "+"
outputInfo "Calculated Body Hash: ${TC_YELLOW}${CALC_BODY_HASH}${TC_NORMAL}" "+"
# Compare the two strings for a match and output the result to the terminal.
# -- RFC standard is to PERMFAIL if the Body Hash doesn't verify, because the Body Hash is used in the next step.
if [[ "${DKIM_BODYHASH}" == "${CALC_BODY_HASH}" ]]; then
  outputResult "Body Hash Match" "+" 0
else
  outputError "${TC_RED}PERMFAIL${TC_NORMAL}: The Body Hash did not verify successfully. Signature is not valid!" 5
fi


# Gather information about the header signing.
echo " +++ Verifying primary DKIM signature (b) with the public key..."
DKIM_HEADER_SIGNATURE=$(getField "b")
TEMP_OUT="/tmp/dkim-verify-$$"
# Decode the Base64 signature.
echo "${DKIM_HEADER_SIGNATURE}" | base64 -di >$TEMP_OUT 2>/dev/null
[ $? -ne 0 ] && outputError "${TC_RED}PERMAIL${TC_NORMAL}: Bad Base64 in the \"b\" tag of the DKIM-Signature header." 16
outputInfo "Base64 decoded." "+"
# Multipart step:
# - Decrypt the hash with OpenSSL's RSA utility.
# - Get the final two lines, cut at the '-' symbols and get fields 2&3.
# - Use sed to (1) delete 2+ spaces and the content following it, (2) remove spaces and dashes.
# - Delete all newline characters to aggregate the hexdump into one string.
DKIM_HEADER_HASH=$(openssl rsautl -inkey ${PUBKEY_FILE} -pubin -in ${TEMP_OUT} -asn1parse 2>/dev/null \
  | tail -2 | cut -d'-' -f2,3 \
  | sed -r 's/\s{2,}.*?$//g' | sed -r 's/(\s|-)//g' | tr -d '\n')
[[ "${DKIM_HEADER_SIGNATURE}" =~ '[^0-9a-zA-Z]' || -z "${DKIM_HEADER_HASH}" ]] && \
  outputError "${TC_RED}PERMFAIL${TC_NORMAL}: Could not decrypt or decipher the header hash value from the \"b\" tag." 15
outputInfo "Header hash decrypted successfully." "+"

echo " +++ Calculating header hash locally..."
# Test the extracted hash (decrypted w/ public key above) against the headers.
DKIM_SIGNED_HEADERS=$(getField "h" |tr ':' ' ' | sed -r 's/\s+/ /g')
DKIM_SIGNED_HEADERS_TEST=$(echo "${DKIM_SIGNED_HEADERS}" | tr '[:upper:]' '[:lower:]')
# Make sure the headers contain SOMETHING besides whitespace.
[ -z "${DKIM_SIGNED_HEADERS}" ] && \
  outputError "${TC_RED}PERMFAIL${TC_NORMAL}: The \"h\" field is empty, there is nothing to sign! This goes against RFC 6367."
if ! [[ "${DKIM_SIGNED_HEADERS_TEST}" == *"from"* ]]; then
  outputError "${TC_RED}PERMFAIL${TC_NORMAL}: The \"h\" field does not contain the From header as required by RFC 6367. Signature is not valid!"
fi

# Reverse the header order.
echo "${CANON_HEADERS}" >/tmp/tempfile
CANON_HEADERS=$(cat /tmp/tempfile | perl -e 'print reverse <>')
echo "${CANON_HEADERS}" >/tmp/tempfile
# Scan from oldest header to newest (purpose of the reversal), and once a matching header is found, strip the line out.
#    No match on a header equals no entry into the FINAL_HEADER_CANON variable.
FINAL_HEADER_CANON=""
DKIM_SIGNED_HEADERS_TEST="${DKIM_SIGNED_HEADERS_TEST} dkim-signaturelast"
IFS=' '
for header in ${DKIM_SIGNED_HEADERS_TEST[@]}; do
#  echo "LOOKUP: $header"
  if [[ "${header}" == "dkim-signaturelast" ]]; then
    if [[ "${DKIM_CANON_HEADER}" == "relaxed" ]]; then
      ADD_N_STRIP=$(grep -Poi '^dkim-signature:.*?$' /tmp/tempfile | tail -1)
    else
      # This is dangerous! It assumes that the "b" field is isolated to its own line and is the last value in the signature!
      INDENTATION_CHAR=$(echo "${DKIM_SIGNATURE_SIMPLE}" | grep -Poi -m1 '^(\s|\t)+.' | sed -r 's/.$//')
      ADD_N_STRIP=$(echo "${DKIM_SIGNATURE_SIMPLE}" | sed -n '/\bb=/q;p')
      ADD_N_STRIP="${ADD_N_STRIP}\n${INDENTATION_CHAR}b="
    fi
  else ADD_N_STRIP=$(grep -Poi -m1 '^'"${header}"':.*?$' /tmp/tempfile); fi
  [ -z "${ADD_N_STRIP}" ] && continue
  sed -ri '/^'"${header}"':/d' /tmp/tempfile
  if [[ "${header}" == "dkim-signature"* ]]; then ADD_N_STRIP=$(echo "${ADD_N_STRIP}" | sed -r 's/\bb=.*?($|;)/b=/'); fi
  echo -ne "${ADD_N_STRIP}\r\n" >>/tmp/tempfile_gen
done

sed -ri 's/\s+$//g' /tmp/tempfile_gen
unix2dos --quiet /tmp/tempfile_gen 2>&1 >/dev/null
truncate -s -2 /tmp/tempfile_gen
CALC_HEADER_HASH=$(`echo ${HASH_ALG}`sum /tmp/tempfile_gen | cut -d' ' -f1)
rm /tmp/tempfile*

# Output results.
outputInfo "Extracted Header Hash:  ${TC_CYAN}${DKIM_HEADER_HASH}${TC_NORMAL}" "+"
outputInfo "Calculated Header Hash: ${TC_CYAN}${CALC_HEADER_HASH}${TC_NORMAL}" "+"
# Compare the two strings for a match and output the result to the terminal.
# -- RFC standard is to PERMFAIL if the Hash doesn't verify; it's the primary signature.
if [[ "${DKIM_HEADER_HASH}" == "${CALC_HEADER_HASH}" ]]; then
  outputResult "Header Hash Match" "+" 0
else
  outputError "${TC_RED}PERMFAIL${TC_NORMAL}: The Header Hash did not verify successfully. Signature is not valid!" 5
fi

# Successful exit.
echo " +++ [${TC_BOLD}${TC_GREEN}SUCCESS${TC_NORMAL}] DKIM Signature is ${TC_GREEN}${TC_BOLD}VALID${TC_NORMAL}!"
exit 0
