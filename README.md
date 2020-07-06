If the installed version of the OpenSSL binary supports the 
#     'ciphers -stdname' parameter then this is used to perform the OpenSSL
#     to IANA cipher suite name conversion, else the 
#     convert_ossl_cipher_suite_name_to_iana.sh script is used.

--------------------------------------------------------------------------------

get_cipher_suites
=================

DESCRIPTION
-----------
`get_cipher_suites.sh` is a Bash script, the purpose of which is to interrogate a
target (URL, hostname, IP, etc) and return a list of supported SSL/TLS cipher 
suites.

The resultant cipher suite list includes both OpenSSL and IANA (Internet Assigned 
Numbers Authority) nomenclature. Behind the scenes, this requires converting
a cipher suite name from its OpenSSL nomenclature to its equivalent IANA name. 
If the installed version of the OpenSSL binary supports the `ciphers -stdname` 
parameter then this is used to perform the conversion, otherwise 
`convert_ossl_cipher_suite_name_to_iana.sh` is called which has a dependency on 
the the official TLS Cipher Suites registry which is maintained by the IANA. 
Consequently if the latter is used then the first time you run the script, 
you'll be prompted to download the registry as a CSV file.

USAGE
-----
```
./get_cipher_suites.sh -t <target> [-p <port_number>] [-n] [-v]

Options:
  -t    Target
  -p    Port number
  -n    Non-interactive
  -v    Verbose
  -h    Help
  -a    About
```

EXAMPLE
-------
```
./get_cipher_suites.sh -t 172.0.0.1

=================
GET CIPHER SUITES
=================

Checking which version(s) of SSL/TLS the installed OpenSSL binary supports...
  * ssl2:   No
  * ssl3:   No
  * tls1:   Yes
  * tls1_1: Yes
  * tls1_2: Yes
  * tls1_3: No

Target: 172.0.0.1, Port: 443

Please wait.....................................................................
................................................................................
.................................................

    | Protocol | OpenSSL Name              | IANA Description
1   | tls1     | ECDHE-RSA-AES256-SHA      | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
2   | tls1     | AES256-SHA                | TLS_RSA_WITH_AES_256_CBC_SHA
3   | tls1     | ECDHE-RSA-AES128-SHA      | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
4   | tls1     | AES128-SHA                | TLS_RSA_WITH_AES_128_CBC_SHA
5   | tls1_1   | ECDHE-RSA-AES256-SHA      | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
6   | tls1_1   | AES256-SHA                | TLS_RSA_WITH_AES_256_CBC_SHA
7   | tls1_1   | ECDHE-RSA-AES128-SHA      | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
8   | tls1_1   | AES128-SHA                | TLS_RSA_WITH_AES_128_CBC_SHA
9   | tls1_2   | ECDHE-RSA-AES256-SHA      | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
10  | tls1_2   | AES256-SHA256             | TLS_RSA_WITH_AES_256_CBC_SHA256
11  | tls1_2   | AES256-SHA                | TLS_RSA_WITH_AES_256_CBC_SHA

Elapsed time: 0:00:54
```

FILES
-----
  * `get_cipher_suites.sh` - The main script.
  * `convert_ossl_cipher_suite_name_to_iana.sh` - Called by `get_cipher_suites.sh`
     to convert an OpenSSL formatted cipher suite name to the description 
     recorded in the official TLS Cipher Suites registry maintained by the IANA 
     (Internet Assigned Numbers Authority).

**NB:** Both scripts must be executable (eg `chmod +x <script>`).

MISC
----
I wrote a blog post to accompany the first release in March 2019: [List the Supported TLS Cipher Suites on a Host](https://www.thecliguy.co.uk/2019/03/10/list-the-supported-tls-cipher-suites-on-a-host)
