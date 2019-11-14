#!/bin/bash

# COMMON.sh
# Description: Provide common functions across multiple scripts in the toolkit.
# Contributors:
#    Notsoano Nimus <postmaster@thestraightpath.email>,
# Repo: https://github.com/NotsoanoNimus/email-security-toolkit/tree/master/common
# Date [of first use]: Never used individually
##############

######################################################################################
# This script should not be used as a standalone module, and is designed to simply
#  supplement the other individual BASH items in the toolkit.
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

# colors
# -- Initialize terminal colors, if enabled.
# ---- Feeding ANY argument to this function will DISABLE colors in the terminal.
# ---- Colors are always defined by TC_{color}; mnemonic being "terminal color {color}".
function colors() {
  [ -n "$1" ] && return
  COLORS=$(tput colors 2>/dev/null)
  if [ -n "${COLORS}" ]; then
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

# A predefined, "global-constant" list of dependencies defined on a per-module basis.
DKIM_DEPS="perl unix2dos openssl base64 dig xxd tr sed sha1sum sha256sum head tail cut truncate"
SPF_DEPS=""
DMARC_DEPS="${DKIM_DEPS} ${SPF_DEPS}"
# checkDependencies
# -- Iterate through a predefined list of dependencies and raise an error if the
# ---- requested module or application is not installed on the system.
# PARAMS: 1 = Space-separated list of required dependencies
function checkDependencies() {
    local DEPENDENCIES="$1"
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

# outputError
# -- Output an error to the terminal and exit with the given code.
# PARAMS: 1 = Accompanying string, 2 = Exit code
function outputError() {
  echo "${TC_BOLD}${TC_RED}ERROR${TC_NORMAL}: $1"
  exit $2
}

# outputResult
# -- Predefine a template for indicating the PASS/FAIL state of something.
# ---- This is mainly used by DKIM-verify at this time, but is included in common for future expansion.
# PARAMS: 1 = Description, 2 = Aesthetic prefix (if any) to include, 3 = (0) PASS, (1) FAIL
function outputResult() {
  printf " ${2}===== $1 [${TC_BOLD}"
  [ $3 -eq 0 ] && printf "${TC_GREEN}PASS" || printf "${TC_RED}FAIL"
  echo "${TC_NORMAL}]"
}

# outputInfo
# -- Output the given info to the terminal as only an informative piece of information.
# PARAMS: 1 = Message to display, 2 = Prefix (if any) to include.
function outputInfo() {
  echo " ${2}\`---> $1"
}

# printNeatly
# -- Sub-function for neat printing.
# PARAMS: 1 - Left column, 2 - Separator, 3 - Right column, 4 - Spread (spaces apart)
function printNeatly() {
    printf "%-${4}s ${2} %s\n" "${1}" "${3}"
}

# getField
# -- Return the value given in the following expression: {tag}={value}
# ---- This form of variable assignment is typical in DNS-based sender authentication (like DMARC and DKIM).
# PARAMS: 1 = variable name, 2 = record value
# RETURN CODES: "" = non-existent field, "[STRING]" = value of variable
# EXAMPLE USAGE: FIELD_VALUE=$(getField "d" "${DKIM_SIGNATURE}")
# ---- Returns the "d=" (domain) value from the DKIM Signature
function getField() {
  # Is the given record value not defined? Leave with null response.
  [ -z "$2" ] && return 0
  # Otherwise, use regex to extract the field's value from the record.
  local RETVAL=$(echo "$2" | grep -Poi '\b'"$1"'=.*?(;|$)' | sed -r 's/;.*//g' | head -n1)
  echo "${RETVAL:`expr ${#1} + 1`:${#RETVAL}}"
}
