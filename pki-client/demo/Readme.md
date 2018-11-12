
# Using shell scripts

You can use the client to get EC and AT certificates from a PKI. This PKI is only for prototype development or for demo, don't use it evilly.

To get an AT certificate, you have to go through different steps:

## Registration

To register an ITS, you need a canonical id and a technical key.

The canonical id can be any string of characters, but must be unique in the EA.

A technical key can be generated with the script `./prepareITS.sh`: run it to produce a file `TechnicalKey` (the name of the file can be modified in the script). Then run the script `./getpubkeyforitsregistration.sh <file_name>` where `<file_name>` is the file containing the technical key (so `TechnicalKey` by default). This second command will display the key in a certain format which will be useful later during the registration.

Please refer to the user guide of the operator interface for the next steps of the registration.

## Enrolment

Before running the script `enrollEC.sh`, you need to modify it, by changing the value of `ITSID` by the canonical id and maybe the value of `TECHNICALKEY` by the file containing the technical key, if you changed it. You can also change the file where the private part of the verification key will be stocked with the variable `ECVERIFICATIONKEY`, and the file which will contain the EC with the variable `ENROLMENTCERTIFICATE`. When the information are correct, you can execute it. The programme shall display the exchanged messages and finally create the two files.

## Authorization

Finally, you can modify the script `enrollAT.sh` by setting the correct values of `ECVERIFICATIONKEY` and `ENROLMENTCERTIFICATE` (nothing to do if you didn't change them). You can also change the variable `ATVERIFICATIONKEY` and `AUTHORIZATIONTICKET` if you want it. When the script is ready, you can run it. Like for the EC, the programme shall display the exchanged messages and create the files (including the one containing the AT).

