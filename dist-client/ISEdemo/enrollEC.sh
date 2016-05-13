#! /bin/sh

###### Bloc de configuration

### Paramètres propres à la EA

EAID=0D88BE8BF72C7E4F
EAENCRYPTIONPUBLICKEY=ISEEAEncryptionKey.pub
EAVERIFICATIONPUBLICKEY=ISEEAVerificationKey.pub
EASERVER=http://52.30.153.183

### Paramètres propres au boitier ITS

TECHNICALKEY=TechnicalKey
ITSID=EE_ITS
AIDSSPLIST=240100250100

# Ces fichiers seront générés
ECVERIFICATIONKEY=ECVerificationKey
ENROLMENTCERTIFICATE=EnrolmentCertificate

### Divers

# Écart actuel entre TAI et UTC (avec epoch TS 103097)
TAIUTC=4

######


echo "====================="
echo "Enrôlement pour un EC"
echo "====================="

if [ ! -f $ECVERIFICATIONKEY ]; then
  echo "Génération de la clé de vérification."
  ../PKIClient genkey --output $ECVERIFICATIONKEY
else
  echo "Clé de vérification EC existante."
fi

RESPDECRKEY=$$.ResponseDecryptionKey
ECREQ=$$.EncapsulatedECRequest.der
ECRESP=$$.EncapsulatedECResponse.der

echo "Génération de la ResponseDecryptionKey."
../PKIClient genkey --output $RESPDECRKEY

echo "Construction de la requête EC"
../PKIClient genECEnroll --technicalkey $TECHNICALKEY --canonicalid $ITSID --verificationkey $ECVERIFICATIONKEY --itsaidssplist $AIDSSPLIST --eakey $EAENCRYPTIONPUBLICKEY --eaid $EAID --responsedecryptionkey $RESPDECRKEY --output $ECREQ --taiutc $TAIUTC --debug

echo "Transmission de la requête à la EA"
curl -v -o $ECRESP --header "Content-type: application/x-its-request" --data-binary @$ECREQ $EASERVER

echo "Extraction de la réponse"
../PKIClient receiveECResponse --input $ECRESP --output $ENROLMENTCERTIFICATE --responsedecryptionkey $RESPDECRKEY --eaverificationkey $EAVERIFICATIONPUBLICKEY --eaid $EAID --request $ECREQ --debug

echo "Suppression de la ResponseDecryptionKey"
rm $RESPDECRKEY

echo "Suppression des requête/réponse"
rm $ECREQ $ECRESP
