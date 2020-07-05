#!/bin/bash

################################################################################
# Copyright (C) 2019 - 2020
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
# get_cipher_suites
#
# PURPOSE
#   Interrogates a specified target to determine which SSL/TLS cipher suites it
#   supports. The results show the OpenSSL and IANA description of each 
#   supported cipher suite.
#
#   Example output:
#   
#   Target: 172.0.0.1, Port: 443
#       | Protocol | OpenSSL Name              | IANA Description
#   1   | tls1     | ECDHE-RSA-AES256-SHA      | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
#   2   | tls1     | AES256-SHA                | TLS_RSA_WITH_AES_256_CBC_SHA
#   3   | tls1     | ECDHE-RSA-AES128-SHA      | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
#   4   | tls1     | AES128-SHA                | TLS_RSA_WITH_AES_128_CBC_SHA
#   5   | tls1_1   | ECDHE-RSA-AES256-SHA      | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
#   6   | tls1_1   | AES256-SHA                | TLS_RSA_WITH_AES_256_CBC_SHA
#   7   | tls1_1   | ECDHE-RSA-AES128-SHA      | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
#   8   | tls1_1   | AES128-SHA                | TLS_RSA_WITH_AES_128_CBC_SHA
#   9   | tls1_2   | ECDHE-RSA-AES256-SHA      | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
#   10  | tls1_2   | AES256-SHA256             | TLS_RSA_WITH_AES_256_CBC_SHA256
#   11  | tls1_2   | AES256-SHA                | TLS_RSA_WITH_AES_256_CBC_SHA
#
# DEPENDENCIES
#   * openssl                                     OpenSSL command line binary.
#
#   * grep                                        A command-line utility for 
#                                                 searching plain-text data sets 
#                                                 for lines that match a regular 
#                                                 expression.
#
#   * tr                                          Translates or deletes 
#                                                 characters. 
#                                                 Present in GNU Core Utilities 
#                                                 (coreutils).
#
#   * convert_ossl_cipher_suite_name_to_iana.sh   A Bash script for converting  
#                                                 cipher suite names from the 
#                                                 OpenSSL format to the 
#                                                 description as recorded in the 
#                                                 official TLS Cipher Suites 
#                                                 registry maintained by the 
#                                                 Internet Assigned Numbers 
#                                                 Authority (IANA). This script
#                                                 is only used if the installed
#                                                 version of OpenSSL lacks the
#                                                 'ciphers -stdname' parameter,
#                                                 which is usually the case
#                                                 prior to OpenSSL 1.1.1.
#
# CAVEATS
#   Periodically OpenSSL adds support for new versions of the TLS protocol and
#   removes support for older versions. It is therefore possible for a target to 
#   support a version (or versions) of TLS that the openssl binary does not, in 
#   which case such version(s) cannot be inspected by this script.
#   Prior to interrogating a specified target, the SSL/TLS protocol versions
#   supported by the openssl binary are listed.
#
################################################################################
# Development Log:
#
# 0.2.0 - 2020-07-05 - Adam Russell
#   * If the installed version of the OpenSSL binary supports the 
#     'ciphers -stdname' parameter then this is used to perform the OpenSSL
#     to IANA cipher suite name conversion, else the 
#     convert_ossl_cipher_suite_name_to_iana.sh script is used.
#
# 0.1.0 - 2019-03-10 - Adam Russell
#   * First release.
#
################################################################################

# Enforces something akin to strict mode.
# e:          Instructs bash to immediately exit if any command returns a
#             non-zero exit code.
# u:          Detects undefined variables and exits.
# o pipefail: Prevents errors in a pipeline from being masked.
set -euo pipefail

usage() {
    echo ""
    echo "Usage:"
    echo "  ${0##*/} -t <target> [-p <port_number>] [-n] [-v]"
    echo ""
    echo "Options:"
    echo "  -t    Target"
    echo "  -p    Port number"
    echo "  -n    Non-interactive"
    echo "  -v    Verbose"
    echo "  -h    Help"
    echo "  -a    About"
    echo ""
}

about() {
    echo "$cScript_Name"
    echo "Version: $cVersion_Number"
    echo ""
    echo "Copyright (C) 2019 - 2020"
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

timer() {
    # Use the date Command to Measure Elapsed Time
    #
    # This function incorporates derivative work covered by the following 
    # copyright and permission notice: 
    #
    #     Copyright 2008 Mitch Frazier <mitch@comwestcr.com>
    #     
    #     This software may be used and distributed according to the terms of 
    #     the MIT License or the GNU General Public License version 2 (or any 
    #     later version).
    #
    # See also: 
    # https://www.linuxjournal.com/content/use-date-command-measure-elapsed-time
    
    # Usage: 
    # If called with no arguments a new timer is returned.
    # If called with arguments the first is used as a timer
    # value and the elapsed time is returned in the form HH:MM:SS.
    
    if [[ "$#" -eq 0 ]]; then
        echo "$(date '+%s')"
    else
        local  stime="$1"
        etime="$(date '+%s')"

        if [[ -z "$stime" ]]; then stime="$etime"; fi

        dt=$((etime - stime))
        ds=$((dt % 60))
        dm=$(((dt / 60) % 60))
        dh=$((dt / 3600))
        printf '%d:%02d:%02d' "$dh" "$dm" "$ds"
    fi
}

IsIanaCsvPresentAndNotEmpty() {
    if [ ! -s "$cIana_Csv_File" ]; then
        echo >&2 "The file '$cIana_Csv_File' does not exist or is empty."
        echo >&2 ""
        echo >&2 "This script has a dependency on the official TLS Cipher Suites"
        echo >&2 "registry CSV maintained by the IANA (Internet Assigned Numbers"
        echo >&2 "Authority)."
        echo >&2 ""
        
        if [ "$noninteractive" -eq 1 ]; then
            echo "To download the file, run the script omitting the -n (non-interactive) parameter."
            exit 1
        else
            while true; do
                read -p "Do you wish to download the file? [Y/n] " yn
                case "$yn" in
                    [Yy]* ) printf "Downloading..."; $("$cOpenssl_To_Iana_Description_Script" -d); printf " Done.\n\n"; break;;
                    [Nn]* ) exit;;
                    * ) echo "Please answer yes or no.";;
                esac
            done
        fi
    fi
}

function TestCipherSuitesAgainstTarget() {
    # This function incorporates derivative work covered by the following 
    # copyright and permission notice: 
    #
    #     BSD 2-clause licence
    #     
    #     Copyright <2015> <INDEPENDENT SECURITY EVALUATORS>
    #     
    #     Redistribution and use in source and binary forms, with or without 
    #     modification, are permitted provided that the following conditions are 
    #     met:
    #     
    #     1. Redistributions of source code must retain the above copyright 
    #     notice, this list of conditions and the following disclaimer.
    #     
    #     2. Redistributions in binary form must reproduce the above copyright 
    #     notice, this list of conditions and the following disclaimer in the 
    #     documentation and/or other materials provided with the distribution.
    #     
    #     THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
    #     "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
    #     LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
    #     A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
    #     HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
    #     SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
    #     LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
    #     DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
    #     THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
    #     (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
    #     OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.  
    #
    # See also: 
    # https://www.securityevaluators.com/using-openssl-determine-ciphers-enabled-server

    
    # Parameters: 
    #     1) The target to interrogate.
    #        Mandatory.
    #     2) The port number.
    #        Mandatory.
    #     3) A space separated string of SSL/TLS versions in OpenSSL format: <SSL|TLS><MAJOR_VER_NO>_<MINOR_VER_NO>.
    #        Mandatory.
    #     4) Use Native OpenSSL to IANA Conversion, where 1 = True.
    #        Mandatory.
    #     5) Verbose, where 1 = True.
    #        Optional.
    
    local intNumberArgs=5
    local columnWidths="%-3s | %-8s | %-29s | %-20s\n"
    local verbose=0
    local opensslexitcode=''
    local ctranslatedexitcode=''
        
    if [ "$#" -eq 0 ] || [ "$#" -gt "$intNumberArgs" ] ; then
        echo >&2 "${FUNCNAME[0]}: Incorrect number of arguments. Supplied: $#, required: $intNumberArgs."
        exit 1
    fi
    
    local target="$1"
    local portnumber="$2"
    
    # Turn the string of space separated SSL/TLS versions into an array.
    local arrTlsVers
    read -ra arrTlsVers <<< "$3"
    
    if [ "$4" -eq 1 ]; then
        local fUseNativeConversion=1
    else
        local fUseNativeConversion=0
    fi
    
    if [ "$5" -eq 1 ]; then
        local verbose=1
    fi
    
    counter=1
    # Loop through each version of the SSL/TLS protocol.
    for v in "${arrTlsVers[@]}"; do
        # Loop through each cipher suite for the given SSL/TLS protocol version.
        for c in $(openssl ciphers 'ALL:eNULL' | tr ':' ' '); do
                                                
            if [ "$verbose" -eq 1 ]; then
                printf "[%(%Y-%m-%d %H:%M:%S)T] Protocol: $v, Cipher Suite (OpenSSL Nomenclature): $c\n"
            else
                printf "."
            fi
                        
            # Use OpenSSL to determine whether the cipher suite is enabled on
            # the specified target, if it is then print a row to the table.
            
            if [ "$verbose" -eq 1 ]; then
                printf "[%(%Y-%m-%d %H:%M:%S)T]  * Testing target for cipher suite...\n"
            fi  
            
            # Temporarily disable exit checking to prevent the script from
            # aborting. This is because if openssl fails to connect to the 
            # target using the specified cipher suite it will produce a non-zero 
            # exit code.
            set +e
            tmpoutput=$(openssl s_client -connect "$target":"$portnumber" \
            -cipher "$c" -"$v" < /dev/null 2>&1 >/dev/null)
            opensslexitcode="$?"
            set -e
            
            if [ "$opensslexitcode" -eq 0 ]; then
                if [ "$verbose" -eq 1 ]; then
                    printf "[%(%Y-%m-%d %H:%M:%S)T]    Enabled: TRUE\n"
                    printf "[%(%Y-%m-%d %H:%M:%S)T]  * Converting OpenSSL name to IANA description...\n"
                fi
                
                # Temporarily disable exit checking to prevent the script from
                # aborting. If the translation from OpenSSL to IANA fails 
                # because the appropriate entry is missing from the IANA CSV
                # file then the conversion script will return a non-zero
                # exit code.
                                
                if [ "$fUseNativeConversion" -eq 1 ]; then
                    set +e
                    ctranslated=$("$cOpenssl_To_Iana_Description_Script" -o $c 2>&1)
                    set -e
                else
                    set +e
                    ctranslated=$("$cOpenssl_To_Iana_Description_Script" -o $c -f "$cIana_Csv_File" 2>&1)
                    set -e
                fi
                
                ctranslatedexitcode="$?"
                
                if [ "$ctranslatedexitcode" -eq 0 ]; then
                    if [ "$verbose" -eq 1 ]; then
                        printf "[%(%Y-%m-%d %H:%M:%S)T]     $ctranslated\n"
                    fi
                else
                    if [ "$verbose" -eq 1 ]; then
                        printf "[%(%Y-%m-%d %H:%M:%S)T]"
                        printf "%-3s %s \n %-23s %s \n" "" "Converting OpenSSL cipher suite name failed." "" "$ctranslated"
                    else
                        printf "\n%s\n%s\n" "Converting OpenSSL cipher suite name '$c' failed." "$ctranslated"
                    fi
                    
                    exit 1
                fi
                
                tableoutput+=$(printf "$columnWidths" "$counter" "$v" "$c" "$ctranslated")
                tableoutput+="\n"
                ((counter++))
            else
                if [ "$verbose" -eq 1 ]; then
                    printf "[%(%Y-%m-%d %H:%M:%S)T]    Enabled: FALSE\n"
                    printf "                         $tmpoutput\n"
                fi
            fi
            
        done
    done
    
    if [ ! -z "$tableoutput" ]; then
        printf "\n\n"
        printf "$columnWidths" "" "Protocol" "OpenSSL Name" "IANA Description"
        printf "$tableoutput\n"
    else
        printf "\n\n"
        printf "Failed to determine any of the cipher suites used by the specified target.\n\n"
    fi
}

GetSupportedProtocolVersionsByOpenSslBinary() {
    ############################################################################
    # Periodically OpenSSL adds support for new versions of TLS and removes
    # support for older versions. Regarding dropping support for older versions,
    # in some cases it may be possible to re-enable support by compiling from
    # source, but in other cases the relevant code may have been removed.
    #
    # Unfortunately there's no clean way to determine which version(s) of SSL/TLS 
    # an OpenSSL binary supports. I've found that running the command 
    # "openssl s_client -<protocol_version>" results in stderr containing
    # "Connection refused" if the protocol version is supported. Whereas if the
    # protocol version is NOT supported, then the resultant stderr typically 
    # contains "unknown option -<protocol_version>" or "null ssl method passed".
    ############################################################################
    # Input:
    #     An array of SSL/TLS protocol versions in OpenSSL format: 
    #       <SSL|TLS><MAJOR_VER_NO>_<MINOR_VER_NO>.
    #
    # Returns:
    #     A space separated list of SSL/TLS versions to stdout.
    #
    # Notes:
    #    To avoid contaminating the return value, all other output should be
    #    emitted to stderr (1>&2).
    ############################################################################
    
    # Turn the space separated list of SSL/TLS versions into an array.
    local arrTlsVers
    read -ra arrTlsVers <<< "$1"
    
    i=0
    printf "Checking which version(s) of SSL/TLS the installed OpenSSL binary supports...\n" 1>&2
    for version in "${arrTlsVers[@]}"; do
        # Redirect StdErr to StdOut and StdOut to dev\null.
        TestProtocolVersion=$(openssl s_client -"$version" 2>&1 | grep "Connection refused")
        
        if [ -z "$TestProtocolVersion" ]; then
            printf "%-11s %-0s \n" "  * $version:" "No" 1>&2
            ####printf "$TestProtocolVersion\n"
            unset arrTlsVers["$i"]
        else
            printf "%-11s %-0s \n" "  * $version:" "Yes" 1>&2
            ####printf "$TestProtocolVersion\n"
        fi
        ((i++))
    done
    
    if [ "${#arrTlsVers[@]}" -eq 0 ]; then
        echo "The installed openssl binary does not support any of the specified SSL/TLS" 1>&2
        echo "protocol versions." 1>&2
        exit 1
    fi

    echo "${arrTlsVers[@]}"
}

main() {    
    local -r cScript_Name='Get Cipher Suites'
    local -r cVersion_Number=0.2.0  
    local -r cOpenssl_To_Iana_Description_Script='./convert_ossl_cipher_suite_name_to_iana.sh'
    local -r cIana_Csv_File='tls-parameters-4.csv'
        
    local SslAndTlsVersions=(ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3)
    local portnumber=443
    local verbose=0
    local noninteractive=0
    local target=''
    local tableoutput=''

    while getopts "t: p: n v h a ?" OPTION
    do
        case "$OPTION" in
            t)
                target="$OPTARG"
                ;;
            p)
                portnumber="$OPTARG"
                ;;
            v)
                verbose=1
                ;;
            n)
                noninteractive=1
                ;;
            h)
                usage
                exit
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

    local underline=; for ((i=0; i<"${#cScript_Name}"; i++)); do underline+="="; done; 
    printf '%s\n' "$underline"
    echo "$cScript_Name" | tr [a-z] [A-Z]
    printf '%s\n\n' "$underline"
        
    if [ "$#" -eq 0 ]; then
        echo >&2 "No parameters provided."
        echo ""
        usage
        exit
    fi
    
    # Target is mandatory.
    if [ -z "$target" ]; then
        usage
        exit
    fi
    
    # Check that openssl is present.
    command -v openssl >/dev/null 2>&1 || { echo >&2 "openssl not found."; exit 1; }

    ############################################################################
    # Check whether openssl supports the 'ciphers -stdname' parameter.
    
    # Temporarily disable exit checking to prevent the script from
    # aborting. This is because if openssl fails to connect to the 
    # target using the specified cipher suite it will produce a non-zero 
    # exit code.
    set +e
    tmpoutput=$(openssl ciphers -stdname < /dev/null 2>&1 >/dev/null)
    opensslexitcode="$?"
    set -e
    
    if [ "$opensslexitcode" -eq 0 ]; then
        fUseNativeOpensslToIanaConversion=1
    else
        fUseNativeOpensslToIanaConversion=0
    fi
    ############################################################################
    
    if [ "$fUseNativeOpensslToIanaConversion" -eq 0 ]; then
        # Check that the OpenSSL name to IANA conversion script is present.
        if [ ! -s "$cOpenssl_To_Iana_Description_Script" ]; then
            echo >&2 "${FUNCNAME[0]}: The file '$cOpenssl_To_Iana_Description_Script' does not exist or is empty."
            exit 1
        fi
        
        # Check that the IANA CSV file is present and not empty.
        IsIanaCsvPresentAndNotEmpty
    fi
        
    # Start the timer here because we if the script is running interactively we
    # don't want to incorporate the time it took to respond to prompts.
    starttime="$(timer)"
    
    # Determine which version(s) of SSL/TLS the OpenSSL binary supports.
    #   How to pass an array to a function as an actual parameter rather than a 
    #   global variable: https://unix.stackexchange.com/questions/183630
    returnVal=$(GetSupportedProtocolVersionsByOpenSslBinary "$(echo ${SslAndTlsVersions[@]})")
    
    # Turn the space separated list of SSL/TLS versions into an array.
    read -ra SupportedProtocolVersions <<< "$returnVal"
    
    printf "\nTarget: $target, Port: $portnumber\n\n"
    
    if [ "$verbose" -eq 0 ]; then
        printf "Please wait"
    else
        printf "Please wait...\n"
    fi
    
    # How to pass an array to a function as an actual parameter rather than a 
    # global variable: https://unix.stackexchange.com/questions/183630
    TestCipherSuitesAgainstTarget "$target" "$portnumber" "$(echo ${SupportedProtocolVersions[@]})" "$fUseNativeOpensslToIanaConversion" "$verbose" 
    
    printf 'Elapsed time: %s\n' "$(timer $starttime)"
}

main "$@"
