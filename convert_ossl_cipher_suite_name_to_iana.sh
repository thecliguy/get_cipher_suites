#!/bin/bash

################################################################################
# Copyright (C) 2019
# Adam Russell <adam[at]thecliguy[dot]co[dot]uk> 
# https://www.thecliguy.co.uk
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
################################################################################
# convert_ossl_cipher_suite_name_to_iana
#
# PURPOSE
#   Converts an OpenSSL formatted cipher suite name to the description recorded 
#   in the official TLS Cipher Suites registry maintained by the IANA (Internet 
#   Assigned Numbers Authority).
#
# HOW IT WORKS
#   The IANA assigns each cipher suite in the registry a unique two-byte value.
#   
#   1. The openssl binary's 'cipher' command includes the value assigned to a 
#      specified cipher suite in its output when the 'even more verbose' (-V) 
#      argument is supplied. 
#   2. The value returned by step 1 is searched for in the CSV file containing 
#      the TLS Cipher Suites registry from the IANA.
#
# DEPENDENCIES
#   * openssl - OpenSSL command line binary.
#   * curl    - cURL is a command-line tool for getting or sending files using 
#               URL syntax.
#   * sed     - Parses and transforms text.
#   * tr      - Translates or deletes characters. Present in GNU Core Utilities 
#               (coreutils).
#   * cut     - A command line utility which is used to extract sections from 
#               each line of input. Present in GNU Core Utilities (coreutils).
#   * grep    - A command-line utility for searching plain-text data sets for 
#               lines that match a regular expression.
#
################################################################################
# Development Log:
#
# 0.1.0 - 2019-03-10 (AR)
#   * First release.
#
################################################################################

# Enforces something akin to strict mode.
# e:          Instructs bash to immediately exit if any command returns a
#             non-zero exit code.
# u:          Detects undefined variables and exits.
# o pipefail: Prevents errors in a pipeline from being masked.
set -euo pipefail

DownloadTlsCipherSuites() {	
	# Parameters: 
	#     1) Output File
	#        Optional. If not supplied, then the downloaded file is named the 
	#        same as the remote file and saved to the current directory.
	#     
	#     2) Overwrite Existing File
	#        Optional. If supplied, will overwrite a file of the same name if it 
	#        exists.
	#		 Pass 1 for True, 0 for False.
	
	local intNumberOfArgs=2
	local OverwriteExistingFile=0

	local -r cIana_Url="https://www.iana.org/assignments/tls-parameters/"
	local -r cIana_File="tls-parameters-4.csv"
	
	# This function accepts two optional arguments.
	if [ "$#" -gt "$intNumberOfArgs" ]; then
		echo >&2 "${FUNCNAME[0]}: Incorrect number of arguments. Supplied: $#, required: 0 or $intNumberOfArgs."
		exit 1
	fi
	
	if [ "$#" -eq "$intNumberOfArgs" ]; then
		if [ "$2" -eq 1 ]; then
			local OverwriteExistingFile=1
		fi
	fi
		
	if [ ! -z "$1" ]; then
		local savedfilename="$1"
	else
		local savedfilename="$cIana_File"
	fi
	
	# If a file of the same name already exists and the overwrite argument has
	# not been provided then exit the function.
	if [ -f "$savedfilename" -a "$OverwriteExistingFile" -eq 0 ]; then
		echo >&2 "${FUNCNAME[0]}: Download failed. The file '$savedfilename' already exists."
		exit 1
	fi
	
	# Check that curl is present.
	command -v curl >/dev/null 2>&1 || { echo >&2 "${FUNCNAME[0]}: curl not found."; exit 1; }
	
	curl -o "$savedfilename" "$cIana_Url$cIana_File" -s --fail --show-error
}

ConvertOpenSslToIana() {
	# Parameters:
	#	1) OpenSSL Cipher Suite Name. 
    #      Mandatory.
	#   2) Path to IANA cipher suite registry CSV file. 
	#      Mandatory.
	
	local intNumberOfArgs=2
		
	# Check that openssl is present.
	command -v openssl >/dev/null 2>&1 || { echo >&2 "openssl not found."; exit 1; }

	# Check that tr is present.
	command -v tr >/dev/null 2>&1 || { echo >&2 "tr not found."; exit 1; }
	
	# Check that cut is present.
	command -v cut >/dev/null 2>&1 || { echo >&2 "cut not found."; exit 1; }
	
	# Check that grep is present.
	command -v grep >/dev/null 2>&1 || { echo >&2 "grep not found."; exit 1; }
	
	# Ensure that the file exists and is not empty.
	if [ ! -s "$2" ]; then		
		echo >&2 "${FUNCNAME[0]}: The file '$2' does not exist or is empty."
		exit 1
	fi

	# Extract the cipher suite's hex code from the openssl output, perform a
	# lookup against the IANA registry and return the description field.
	openssl ciphers -V "$1" | tr -d '[:space:]' | cut -d '-' -f1 | while read CipherSuiteHexCode; do
		grep "$CipherSuiteHexCode" "$2" | cut -d ',' -f3
	done
}

about() {
    echo "$cScript_Name"
	echo "Version: $cVersion_Number"
	echo ""
	echo "Copyright (C) 2019"
    echo "Adam Russell <adam[at]thecliguy[dot]co[dot]uk>"
    echo "https://www.thecliguy.co.uk"
    echo ""
    echo "This program is free software: you can redistribute it and/or modify"
    echo "it under the terms of the GNU General Public License as published by"
    echo "the Free Software Foundation, either version 3 of the License, or"
    echo "(at your option) any later version."
    echo ""
    echo "This program is distributed in the hope that it will be useful,"
    echo "but WITHOUT ANY WARRANTY; without even the implied warranty of"
    echo "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the"
    echo "GNU General Public License for more details."
    echo ""
    echo "You should have received a copy of the GNU General Public License"
    echo "along with this program.  If not, see <https://www.gnu.org/licenses/>."
}

usage() {
	echo "Usage:"
	echo "This script has two modes of operation, each of which require a different"
	echo "combination of options."
    echo ""
	echo "1. Download the official TLS Cipher Suites registry from the IANA (Internet"
    echo "   Assigned Numbers Authority) as a CSV file."
	echo ""
	echo "   ${0##*/} -d [-f <output_file>] [-c] [-v]"
	echo ""
	echo "2. Convert a specified OpenSSL formatted cipher suite name to the description"
    echo "   recorded in the official TLS Cipher Suites registry CSV file."
    echo ""
    echo "   ${0##*/} -o <openssl_cipher_suite_name> -f <input_file> [-v]"
    echo ""
    echo "Options:"
    echo "  -d    Download"
    echo "  -o    OpenSSL cipher suite name"
    echo "  -f    File - Can denote either an input or output file depending on context"
    echo "  -c    Clobber - Will overwrite an existing file"
    echo "  -h    Help"
	echo "  -a    About"
    echo ""
}

main() {
	local -r cScript_Name='Convert Cipher Suite Name from OpenSSL to IANA'
	local -r cVersion_Number=0.1.0
	
	local action=''
	local clobberfile=0
	local file=''
	
	# Useful info regarding mutually exclusive parameters:
	# https://stackoverflow.com/questions/21721070
	
	while getopts "h d o: f: c a ?" OPTION
    do
        case "$OPTION" in
            h)
                usage
                exit
                ;;
			d)
				[[ -n "$action" ]] && usage || action='download'
                ;;
            o)
                [[ -n "$action" ]] && usage || action='convert'
				local opensslciphersuite="$OPTARG"
                ;;
            f)
                file="$OPTARG"
                ;;
            c)
                clobberfile=1
                ;;
			a)
                about
                exit
                ;;
            ?)
                usage
                exit
                ;;
			*)
				echo >&2 "Invalid option(s) provided"
				echo ""
				usage
				exit 1
				;;
        esac
    done
	
	if [ "$#" -eq 0 ]; then
		echo >&2 "No parameters provided."
		usage
		exit
	fi
	
	case "$action" in
		download) 
			DownloadTlsCipherSuites "$file" "$clobberfile"
			exit
			;;
		convert) 
			ConvertOpenSslToIana "$opensslciphersuite" "$file"
			exit
			;;
		*)
			usage
			exit 1
			;;
	esac
}

main "$@"
