
# Using pki-client
 
## Introduction
 
This client sample allows the interaction with PKI by requesting certificates: EC (enroll credential) or AT (authorization ticket). The code is written in C.

This client is implemented in accordance to ETSI specifications (TS 103 097) and used for the PKI tests in both cooperative ITS projects (ISE and SCOOP@F).
 
## Compilation
 
You need `make` and `gcc` to compile this client. Also, the client must be compiled whith OpenSSL 1.0.2. Probably your system has not an updated version (you can check with `openssl version`), you can only compile sources and link this client with. To do that, [download OpenSSL sources](https://www.openssl.org/source/), configure and compile and create an environment variable `OPENSSL_HOME` with the path to the root directory of this updated OpenSSL sources.
 
To compile the client, use command `make` in a unix environnement in the sources directory.
 
## Quick start using existing shell scripts
 
Once the client compiled, some shell scripts in ISEdemo directory can be used to simulate the complete communication to EA and AA.
 
 * `./prepareITS.sh` generates an ITS Technical key.
 * `./getpubkeyforitsregistration.sh <file_name>` converts the ITS Technical public key in DER format.
 * `./enrollEC.sh` requests a certificate enrollment.
 * `./enrollAT.sh` requests an autorization ticket.

To request a certificate EC or AT, the ITS must be recorded at the EC. The communication requires the EA and AA public key for verification and encryption, also the access points.

## PKIClient
 
 Once the client compiled, all operations to create main application for running the client can be executed using the following command:
 ```
 ./PKIClient [function_name] [options]
 ```

`function_name` can be:

 * `genkey` generates a key on curve ECprime256.
     * Arguments:
         * `-o , --output <file_name>` set the output file
         * `-c , --compressed` get a compressed key
         * `-e , --explicitcurve` use explicit EC curve
 * `genECEnroll`: generates an EC enroll request.
     * Arguments:
         * `-i , --canonicalid <value>` ID of the ITS (its canonical name)
         * `-d , --responsedecryptionkey <file_name>` private key used to decrypt the response from the EA
         * `-v , --verificationkey <file_name>` ITS verification private key to be enrolled
         * `-p , --itsaidssplist <hex value>` ITS profile AID/SSP list in hex
         * `-e , --encryptionkey <file_name>` ITS encryption private key to be enrolled [optional]
         * `-r , --validityrestrictions <hex value>` geographic or temporal restrictions [optional]
         * `-o , --output <file_name>` the file name for the output data
         * `-k , --technicalkey <file_name>` input the signer Technical private key
         * `-R , --eaid <8 bytes hex value>` input the hashedID8 of EA public certificate
         * `-K , --eakey <file_name>` input EA encryption public key
         * `-t , --taiutc <value>` difference between TAI and UTC time.
 * `receiveECResponse`: receive and read an EC enroll.
     * Arguments:
         * `-i , --input <file_name>` the DER file name received from the EA
         * `-o , --output <file_name>` the file name for the output data
         * `-k , --responsedecryptionkey <file_name>` private key used to encrypt the response of the EA
         * `-v , --eaverificationkey <file_name>` EA public key for verification
         * `-e , --eaid <8 bytes hex value>` input the hashedID8 of EA public certificate
         * `-r , --request <file_name>` the DER file sent for enrollment request [optional]
 * `genATEnroll`: generates the shared AT request.
     * Arguments:
         * `-k , --signaturekey <file_name>` ITS enrolled private key
         * `-d , --responsedecryptionkey <file_name>` private key used to encrypt the response of the AA
         * `-v , --verificationkey <file_name>` ITS verification private key to be given authorization
         * `-e , --encryptionkey <file_name>` ITS encryption private key to be given authorization
         * `-p , --itsaidssplist <hex value>` ITS profile AID/SSP list in hex
         * `-r , --validityrestrictions <hex value>` geographic or temporal restrictions [optional]
         * `-R , --eaid <8 bytes hex value>` input the hashedID8 of EA public certificate
         * `-K , --eaencryptionkey <file_name>` EA public key for encryption
         * `-a , --aaid <8 bytes hex value>` input the hashedID8 of AA public certificate
         * `-A , --aaencryptionkey <file_name>` AA public key for encryption
         * `-o , --output <file_name>` the file name for the output data
         * `-s , --start <integer>` choose a desired start date and time [optional]
         * `-t , --taiutc <value>` difference between TAI and UTC time
         * `-c , --enrolmentcertificate <file_name>` ITS enrolled certificate
 * `receiveATResponse`: receive the AT.
     * Arguments:
         * `-i , --input <file_name>` the DER file name received from the AA
         * `-o , --output <file_name>` the file name for the output data
         * `-k , --responsedecryptionkey <file_name>` private key used to encrypt the response of the AA
         * `-v , --eaverificationkey <file_name>` AA public key for verification
         * `-e , --eaid <8 bytes hex value>` input the hashedID8 of AA public certificate
         * `-r , --request <file_name>` the DER file sent for authorization request [optional]
 
**N.B: Any function can take arguments: `--help` and `--debug`.**
 
