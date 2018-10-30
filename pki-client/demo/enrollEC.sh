#! /bin/sh

###### Configuration bloc

### EA parameters

EAID=0D88BE8BF72C7E4F
EAENCRYPTIONPUBLICKEY=ISEEAEncryptionKey.pub
EAVERIFICATIONPUBLICKEY=ISEEAVerificationKey.pub
EASERVER=http://52.30.153.183

### ITS parameters

TECHNICALKEY=TechnicalKey
ITSID=CLIENT-TEST
AIDSSPLIST=240100250100

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
