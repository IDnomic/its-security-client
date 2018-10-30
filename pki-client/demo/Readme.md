
# Using shell scripts

You can use the client to get EC and AT certificates from a PKI. This PKI is only for prototype development or for demo, don't use it evilly.

To get an AT certificate, you have to go through different steps:

## Registration

To register an ITS, you need a canonical id and a technical key.

The canonical id can be any string of characters, but must be unique in the EA: you cannot unregister an ITS and you don't have access to the ITS already registered. So, when you choose an canonical id, be creative (i.e. use your company's name as a prefix).

A technical key can be generated with the script `./prepareITS.sh`: run it to produce a file `TechnicalKey` (the name of the file can be modified in the script). Then run the script `./getpubkeyforitsregistration.sh <file_name>` where `<file_name>` is the file containing the technical key (so `TechnicalKey` by default). This second command will display the key in a certain format which will be useful later.

With this information, you can go to [http://demo.itspki.innovation.keynectis.net ](http://demo.itspki.innovation.keynectis.net), then click on the menu "ITS-S Lifecycle". This site is a demonstration of the PKI, which simulates the lifecycle of an ITS, but it can also be used to register an external ITS. In the first step "MANUFACTURE", please set the chosen canonical id and the public part of the technical key (formatted as the output of `getpubkeyforitsregistration.sh`). Choose a profile (e.g. "Emergency") and click on "Register". If the button become green and checked, the registration has been a success, otherwise a problem has occurred: maybe the canonical id is already used, or the technical key is not in the correct format.

## Enrolment

Before running the script `enrollEC.sh`, you need to modify it, by changing the value of `ITSID` by the canonical id and maybe the value of `TECHNICALKEY` by the file containing the technical key, if you changed it. You can also change the file where the private part of the verification key will be stocked with the variable `ECVERIFICATIONKEY`, and the file which will contain the EC with the variable `ENROLMENTCERTIFICATE`. When the information are correct, you can execute it. The programme shall display the exchanged messages and finally create the two files.

## Authorization

Finally, you can modify the script `enrollAT.sh` by setting the correct values of `ECVERIFICATIONKEY` and `ENROLMENTCERTIFICATE` (nothing to do if you didn't change them). You can also change the variable `ATVERIFICATIONKEY` and `AUTHORIZATIONTICKET` if you want it. When the script is ready, you can run it. Like for the EC, the programme shall display the exchanged messages and create the files (including the one containing the AT).

