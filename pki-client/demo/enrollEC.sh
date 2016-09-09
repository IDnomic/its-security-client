#! /bin/sh

###### Configuration bloc

### EA parameters

EAID=0AC8157DDCAD3F78
EAENCRYPTIONPUBLICKEY=EAEncryptionKey.pub
EAVERIFICATIONPUBLICKEY=EAVerificationKey.pub
EASERVER=http://ea-plugtests.irt-ise-pki.org

### ITS parameters

TECHNICALKEY=TechnicalKey
ITSID=CLIENT-TEST
AIDSSPLIST=240100250100

# Generated files
ECVERIFICATIONKEY=ECVerificationKey
ENROLMENTCERTIFICATE=EnrolmentCertificate

### Others

# TAI - UTC diff
TAIUTC=4

######


echo "====================="
echo "EC request"
echo "====================="

if [ ! -f $ECVERIFICATIONKEY ]; then
  echo "Verification key generation."
  ../PKIClient genkey --output $ECVERIFICATIONKEY
else
  echo "Existing verification key."
fi

RESPDECRKEY=$$.ResponseDecryptionKey
ECREQ=$$.EncapsulatedECRequest.der
ECRESP=$$.EncapsulatedECResponse.der

echo "Response key generation."
../PKIClient genkey --output $RESPDECRKEY

echo "Request building."
../PKIClient genECEnroll --technicalkey $TECHNICALKEY --canonicalid $ITSID --verificationkey $ECVERIFICATIONKEY --itsaidssplist $AIDSSPLIST --eakey $EAENCRYPTIONPUBLICKEY --eaid $EAID --responsedecryptionkey $RESPDECRKEY --output $ECREQ --taiutc $TAIUTC --debug

echo "Request sending."
curl -v -o $ECRESP --header "Content-type: application/x-its-request" --data-binary @$ECREQ $EASERVER

echo "Response reading."
../PKIClient receiveECResponse --input $ECRESP --output $ENROLMENTCERTIFICATE --responsedecryptionkey $RESPDECRKEY --eaverificationkey $EAVERIFICATIONPUBLICKEY --eaid $EAID --request $ECREQ --debug

echo "Clean up."
rm $RESPDECRKEY $ECREQ $ECRESP
