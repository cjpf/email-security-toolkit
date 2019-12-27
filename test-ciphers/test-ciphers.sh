#!/bin/bash

# TEST-CIPHERS.sh
# Description: Check the supported cipher suite for the targeted server, protocol dynamically selected based on port.
# Addendum/Additional: If you want to shadow this output to another file, use the "tee" command like so: ./test_ciphers_dynamic.sh server:port \| tee "outfile"
# Contributors:
#    Notsoano Nimus <postmaster@thestraightpath.email>
# Repo: https://github.com/NotsoanoNimus/email-security-toolkit/tree/master/test-ciphers
# Date [of first use]: 13 January, 2019
#################

######################################################################################
# test-ciphers is a script to gather information on the supported TLS ciphers of
#  a target service port on a destination server.
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



# Script usage information.
function usage() {
  echo "USAGE: $0 <server-to-check>:<port> i.e. mail.example.com:25"
  echo "  Check and report all supported ciphers on a destination server port."
  echo "  Use the -n option to strip any colors (useful with the 'tee' command)."
  exit 1
}


# Check argument count, verify only the limited amount is passed.
[[ $# -ge 3 || $# == 0 || "${1:0:1}" == "-" ]] && usage

# Capture the first value and then shift it off.
SERVER=$1
shift
# Check for erroneous parameters and for the no-color option
NO_COLORS=
while getopts n param; do
  case $param in
    n) NO_COLORS="TRUE" ;;
    *) usage ;;
  esac
done

# If colors are supported and the "no-color" flag is unset, enable them.
colors "${NO_COLORS}"

# Ensuring the given argument includes a port number.
SERVER_HAS_PORT=$(echo "$SERVER" | grep -o ':')
SERVER_PORT=0$(echo "$SERVER" | cut -f2 -d':' -s)
if [[ "$SERVER_HAS_PORT" != ":" || $SERVER_PORT == 0 ]]; then
	echo "$0: ${TC_RED}ERROR${TC_NORMAL}: Please include a port number. For example, mail.example.com:25"
	exit 1
elif ! [[ "$SERVER_PORT" =~ ^[0-9]+$ ]]; then
	echo "$0: ${TC_RED}ERROR${TC_NORMAL}: Please make sure the port is numeric."
	exit 1
fi

SERVER_PORT=$(echo $SERVER_PORT | cut -f2 -d'0' -s)

echo "Checking supported ciphers for: $SERVER"
DELAY=1
ciphers=$(openssl ciphers 'ALL:eNULL' | sed -e 's/:/ /g')

echo "Obtaining cipher list from $(openssl version)..."

# Create a SWITCH-CASE statement here based on the port targeted.
case $SERVER_PORT in
    25|587|465)
        echo "Test type is ${TC_CYAN}SMTP${TC_NORMAL} with STARTTLS!"
        TC_FLAGS="-starttls smtp"
        ;;
    143|993)
        echo "Test type is ${TC_YELLOW}IMAP(S)${TC_NORMAL} with STARTTLS!"
        TC_FLAGS="-starttls imap"
        ;;
    443)
        echo "Test type is ${TC_RED}HTTPS${TC_NORMAL}!"
        TC_FLAGS=
        ;;
    21|990)
        echo "Test type is ${TC_GREEN}FTP(S)${TC_NORMAL} with STARTTLS!"
        TC_FLAGS="-starttls ftp"
        ;;
    389|636)
        echo "Test type is ${TC_WHITE}LDAP(S)${TC_NORMAL} with STARTTLS!"
        TC_FLAGS="-starttls ldap"
        ;;
    110|995)
        echo "Test type is ${TC_BLUE}POP3(S)${TC_NORMAL} with STARTTLS!"
        TC_FLAGS="-starttls pop3"
        ;;
esac

# Execute tests!
for cipher in ${ciphers[@]}; do
  echo -n "Testing $cipher... "
  result=$(echo -n | openssl s_client -cipher "$cipher" -connect $SERVER $TC_FLAGS 2>&1)
  if [[ "$result" =~ ":error:" ]] ; then
    error=$(echo -n $result | cut -d':' -f6)
    echo "${TC_RED}NO${TC_NORMAL} ($error)"
  else
    if [[ "$result" =~ "Cipher is ${cipher}" || "$result" =~ "Cipher    :" ]] ; then
      PROTOCOL=$(echo "$result" | tr '\n' ' ' | sed -r 's/.*Protocol\s+:\s+//g' | sed -r 's/\s+Cipher\s+:.*//g')
      echo "${TC_GREEN}YES${TC_NORMAL} (${PROTOCOL})"
    else
      echo "UNKNOWN RESPONSE (possible connection throttling by server)"
      #echo "$result"
    fi
  fi
  sleep $DELAY
done

printf "\n\nTesting suites: ${TC_YELLOW}SSLv3, TLSv1, TLSv1.1, TLSv1.2${TC_NORMAL}\n"
# Test complete suites/SSL versions.
SUITES="ssl3 tls1 tls1_1 tls1_2"
for suite in ${SUITES[@]}; do
  echo -n "Testing $suite... "
  result=$(echo -n | openssl s_client -connect $SERVER $TC_FLAGS -$suite 2>&1)
  if [[ "$result" =~ "Cipher is (NONE)" ]]; then
    error=$(echo -n $result | cut -d':' -f6)
    echo "${TC_RED}NO${TC_NORMAL} ($error)"
  else
    if [[ "$result" =~ "Cipher is ${cipher}" || ! "$result" =~ 'Cipher\s+:\s+0{4}' ]]; then
      echo "${TC_GREEN}YES${TC_NORMAL}"
    else
      echo "UNKNOWN RESPONSE (possible connection throttling by server)"
      #echo "$result"
    fi
  fi
  sleep $DELAY
done

printf "\n\nTests complete!\n"
