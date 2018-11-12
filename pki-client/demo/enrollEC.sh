#! /bin/sh

###### Configuration bloc

### EA parameters

EAID=A4F37732A5D7A095
EAENCRYPTIONPUBLICKEY=VisteonEAEncryptionKey.pub
EAVERIFICATIONPUBLICKEY=VisteonEAVerificationKey.pub
EASERVER=http://ea-visteon.integration.innovation.keynectis.net

### ITS parameters

TECHNICALKEY=TechnicalKey
ITSID=ITS-CLIENT-TEST # XXX CHANGE ME!
AIDSSPLIST=2403000000250400000000

# Generated files
ECVERIFICATIONKEY=ECVerificationKey
ENROLMENTCERTIFICATE=EnrolmentCertificate

### Others

# TAI - UTC diff
TAIUTC=5

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
