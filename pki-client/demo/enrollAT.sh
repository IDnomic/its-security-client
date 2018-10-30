#! /bin/sh

###### Configuration bloc

### EA parameters

EAID=0D88BE8BF72C7E4F
EAENCRYPTIONPUBLICKEY=ISEEAEncryptionKey.pub

### AA parameters

AAID=518CC02CA2F5BFDF
AAENCRYPTIONPUBLICKEY=ISEAAEncryptionKey.pub
AAVERIFICATIONPUBLICKEY=ISEAAVerificationKey.pub
AASERVER=http://52.30.172.70

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
