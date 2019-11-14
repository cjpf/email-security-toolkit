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

