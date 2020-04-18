cacse.crt
- CA's certificate
- extract this to get CA's public key
example.org.key
- server's private key in plain text
- generated with openssl
example.org.pubkey
- server's public key in plain text
- generated with openssl
example.org.csr
- server's certificate signing request
- contains everything about server's private key, public key
example-19fb0430-7c8f-11ea-ae9d-89114163ae84.crt
- signed server's public key
- signed by CA
- should be sent to clients
- client able to verify with CA's public key
- client to extract this to get server's public key
private_key.der
- server's private key in binary format
- to be read by java security library