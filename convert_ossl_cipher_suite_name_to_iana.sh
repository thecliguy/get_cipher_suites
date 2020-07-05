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
#   * tr      - Translates or deletes characters. Present in GNU Core Utilities 
#               (coreutils).
#   * cut     - A command line utility which is used to extract sections from 
#               each line of input. Present in GNU Core Utilities (coreutils).
#   * grep    - A command-line utility for searching plain-text data sets for 
#               lines that match a regular expression.
#   * wc      - Word Count, reads either standard input or a list of files.
#
################################################################################
# Development Log:
#
# 0.2.0 - 2020-07-05 - Adam Russell
#
#   * Removed the nonexistent parameter '-v' from the examples present in the 
#     usage text.
#
#   * If the -o (openssl cipher suite name) parameter is specified without the 
#     '-f' (file) parameter then OpenSSL to IANA cipher suite name conversion
#     is attempted using OpenSSL's 'ciphers -stdname' parameter. 
#     NB: Prior to OpenSSL 1.1.1 builds generally didn't have 'ciphers -stdname' 
#     available by default, see https://www.openssl.org/docs/man1.1.1/man1/ciphers.html:
#       "The -stdname is only available if OpenSSL is built with tracing enabled 
#       (enable-ssl-trace argument to Configure) before OpenSSL 1.1.1."
#
#   * Starting in OpenSSL version 1.1.1, multiple results are returned when 
#     attempting to return the description of a cipher suite.
#
#     Eg: $ openssl version | tr '[:lower:]' '[:upper:]'
#         OPENSSL 1.0.2G  1 MAR 2016
#         $ openssl ciphers -V ECDHE-RSA-AES256-SHA
#                   0xC0,0x14 - ECDHE-RSA-AES256-SHA    SSLv3 Kx=ECDH     Au=RSA  Enc=AES(256)  Mac=SHA1
#
#         $ openssl version | tr '[:lower:]' '[:upper:]'
#         OPENSSL 1.1.0L  10 SEP 2019
#         $ openssl ciphers -V ECDHE-RSA-AES256-SHA
#                   0xC0,0x14 - ECDHE-RSA-AES256-SHA    TLSv1 Kx=ECDH     Au=RSA  Enc=AES(256)  Mac=SHA1
#
#         $ openssl version | tr '[:lower:]' '[:upper:]'
#         OPENSSL 1.1.1  11 SEP 2018
#         $ openssl ciphers -V ECDHE-RSA-AES256-SHA
#                   0x13,0x02 - TLS_AES_256_GCM_SHA384  TLSv1.3 Kx=any      Au=any  Enc=AESGCM(256) Mac=AEAD
#                   0x13,0x03 - TLS_CHACHA20_POLY1305_SHA256 TLSv1.3 Kx=any      Au=any  Enc=CHACHA20/POLY1305(256) Mac=AEAD
#                   0x13,0x01 - TLS_AES_128_GCM_SHA256  TLSv1.3 Kx=any      Au=any  Enc=AESGCM(128) Mac=AEAD
#                   0xC0,0x14 - ECDHE-RSA-AES256-SHA    TLSv1 Kx=ECDH     Au=RSA  Enc=AES(256)  Mac=SHA1
#
#     To workaround this, ConvertOpenSslToIana has been updated to call the
#     command as follows: openssl ciphers -V | grep " <cipher suite name> "
#     
#     Eg: $ openssl version | tr '[:lower:]' '[:upper:]'
#         OPENSSL 1.1.1  11 SEP 2018
#         $ openssl ciphers -V | grep " ECDHE-RSA-AES256-SHA "
#                   0xC0,0x14 - ECDHE-RSA-AES256-SHA    TLSv1 Kx=ECDH     Au=RSA  Enc=AES(256)  Mac=SHA1
#
# 0.1.0 - 2019-03-10 - Adam Russell
#
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
    #        Pass 1 for True, 0 for False.
    
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
    #   1) OpenSSL Cipher Suite Name. 
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
    
    # Check that wc is present.
    command -v wc >/dev/null 2>&1 || { echo >&2 "wc not found."; exit 1; }
    
    # Ensure that the file exists and is not empty.
    if [ ! -s "$2" ]; then      
        echo >&2 "${FUNCNAME[0]}: The file '$2' does not exist or is empty."
        exit 1
    fi

    # Extract the cipher suite's hex code from the openssl output, perform a
    # lookup against the IANA registry and return the description field.
    #### ciphers -V "$1" | tr -d '[:space:]' | cut -d '-' -f1 | while read CipherSuiteHexCode; do
    cipherSuiteDescription=$(openssl ciphers -V | grep " $1 " 2>&1)
    
    # The output should only ever return one row.
    if [ $(echo "$cipherSuiteDescription" | wc -l) -eq 1 ]; then
        echo "$cipherSuiteDescription" | tr -d '[:space:]' | cut -d '-' -f1 | while read CipherSuiteHexCode; do
            grep "$CipherSuiteHexCode" "$2" | cut -d ',' -f3
        done
    fi
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

usage() {
    echo ""
    echo "Usage:"
    echo ""
    echo "  This script has two modes of operation, each of which require a different"
    echo "  combination of options."
    echo ""
    echo "  1. Convert a an OpenSSL formatted cipher suite name to it's IANA (Internet"
    echo "     Assigned Numbers Authority) description."
    echo ""
    echo "     This can be accomplished using either OpenSSL's native ability to retrieve"
    echo "     a cipher suite's 'standard name' or by referencing the IANA's official TLS"
    echo "     Cipher Suites registry in the form of a CSV file."
    echo ""
    echo "     The former technique should work against OpenSSL 1.1.1+ and is achieved by"
    echo "     omitting the '-f' parameter. Whereas the latter should work against any"
    echo "     version of OpenSSL and is achieved by using the '-f' parameter, where the" 
    echo "     accompanying value is the path to the IANA Cipher Suites registry CSV file." 
    echo ""
    echo "     ${0##*/} -o <openssl_cipher_suite_name> [-f <input_file>]"
    echo ""
    echo "     To obtain the IANA TLS Cipher Suites registry CSV file, see details below."
    echo ""
    echo "  2. Download the official TLS Cipher Suites registry from the IANA as a CSV"
    echo "     file."
    echo ""
    echo "     ${0##*/} -d [-f <output_file>] [-c]"
    echo ""
    echo "Options:"
    echo ""
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
    local -r cVersion_Number=0.2.0
    
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
        echo -e >&2 "No parameters provided.\n"
        usage
        exit
    fi
    
    case "$action" in
        download) 
            DownloadTlsCipherSuites "$file" "$clobberfile"
            exit
            ;;
        convert)
            if [ "$file" == '' ]; then
                # Check whether openssl supports the 'ciphers -stdname' parameter.
                
                # Temporarily disable exit checking to prevent the script from
                # aborting. This is because if openssl fails to connect to the 
                # target using the specified cipher suite it will produce a non-zero 
                # exit code.
                set +e          
                cipherInformationOutput=$(openssl ciphers -stdname 2>&1)
                opensslexitcode="$?"            
                set -e
                
                if [ "$opensslexitcode" -eq 0 ]; then
                    ####echo "AAA: Native conversion."
                    returnVal=$(echo "$cipherInformationOutput" | grep " $opensslciphersuite " | cut -d '-' -f1)
                    echo "$returnVal"
                else
                    >&2 echo "The installed OpenSSL binary does not facilitate native conversion. You must supply the '-f' parameter."
                    exit 1
                fi
            else
                ####echo "BBB: CSV file conversion."
                ConvertOpenSslToIana "$opensslciphersuite" "$file"
            fi
            
            exit
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
