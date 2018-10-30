#! /bin/sh

###### Configuration bloc

### EA parameters

EAID=A3C60C5FCDC4FAE5
EAENCRYPTIONPUBLICKEY=DemoEAEncryptionKey.pub

### AA parameters

AAID=69C94DBD7B6F0BBB
AAENCRYPTIONPUBLICKEY=DemoAAEncryptionKey.pub
AAVERIFICATIONPUBLICKEY=DemoAAVerificationKey.pub
AASERVER=http://aa.itspki.innovation.keynectis.net

### ITS parameters

AIDSSPLIST=2403000000250400000000
ECVERIFICATIONKEY=ECVerificationKey
ENROLMENTCERTIFICATE=EnrolmentCertificate

# Generated files
ATVERIFICATIONKEY=ATVerificationKey
AUTHORIZATIONTICKET=AuthorizationTicket

### Others

# TAI - UTC diff
TAIUTC=5

######


echo "====================="
echo "AT request"
echo "====================="

if [ ! -f $ATVERIFICATIONKEY ]; then
  echo "Verification key generation."
  ../PKIClient genkey --output $ATVERIFICATIONKEY
else
  echo "Existing verification key."
fi

RESPDECRKEY=$$.ResponseDecryptionKey
ATREQ=$$.EncapsulatedATRequest.der
ATRESP=$$.EncapsulatedATResponse.der

echo "Response key generation."
../PKIClient genkey --output $RESPDECRKEY

echo "Request building."
../PKIClient genATEnroll -c $ENROLMENTCERTIFICATE -k $ECVERIFICATIONKEY -d $RESPDECRKEY -v $ATVERIFICATIONKEY -p $AIDSSPLIST -R $EAID -K $EAENCRYPTIONPUBLICKEY -a $AAID -A $AAENCRYPTIONPUBLICKEY -o $ATREQ --taiutc $TAIUTC --debug

echo "Request sending."
curl -v -o $ATRESP --header "Content-type: application/x-its-request" --data-binary @$ATREQ $AASERVER

echo "Response reading."
../PKIClient receiveATResponse --input $ATRESP --output $AUTHORIZATIONTICKET --responsedecryptionkey $RESPDECRKEY --aaverificationkey $AAVERIFICATIONPUBLICKEY --aaid $AAID --request $ATREQ --debug

echo "Clean up."
rm $RESPDECRKEY $ATREQ $ATRESP
