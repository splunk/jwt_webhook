[jwtwebhook://<name>]
* Configure an input for retrieving information from a webhook request

secret = <value>
* The secret key to decode the JWT encoded payload

port = <value>
* The port to run the input on

path = <value>
* A wildcard that must match the path of the jwtwebhooks request
* Example: /my_jwtwebhook/*

cert_file = <value>
* A path to an SSL certificate file. Including this will cause the app to use SSL/TLS.
* The file typically uses the file extension of either .DER, .PEM, .CRT, or .CER
* The path will be interpreted relative to the SPLUNK_HOME path if it is relative
* Example: etc/auth/splunkweb/cert.pem

key_file = <value>
* A wildcard that must match the path of the jwtwebhooks request
* The file typically uses the file extension of .KEY
* The path will be interpreted relative to the SPLUNK_HOME path if it is relative
* Example: etc/auth/splunkweb/privkey.pem


password = <value>
* A password to decrypt the private key if encrypted
* Leave it empty if the private key is not encrypted
