#! /bin/sh

###### Bloc de configuration

### Paramètres propres à la EA

EAID=0D88BE8BF72C7E4F
EAENCRYPTIONPUBLICKEY=ISEEAEncryptionKey.pub

### Paramètres propres à la AA

AAID=518CC02CA2F5BFDF
AAENCRYPTIONPUBLICKEY=ISEAAEncryptionKey.pub
AAVERIFICATIONPUBLICKEY=ISEAAVerificationKey.pub
AASERVER=http://52.30.172.70

### Paramètres propres au boitier ITS

AIDSSPLIST=240100250100
ECVERIFICATIONKEY=ECVerificationKey
ENROLMENTCERTIFICATE=EnrolmentCertificate

# Ces fichiers seront générés
ATVERIFICATIONKEY=ATVerificationKey
AUTHORIZATIONTICKET=AuthorizationTicket

### Divers

# Écart actuel entre TAI et UTC (avec epoch TS 103097)
TAIUTC=4

######


echo "====================="
echo "Enrôlement pour un AT"
echo "====================="

if [ ! -f $ATVERIFICATIONKEY ]; then
  echo "Génération de la clé de vérification."
  ../PKIClient genkey --output $ATVERIFICATIONKEY
else
  echo "Clé de vérification AT existante."
fi

RESPDECRKEY=$$.ResponseDecryptionKey
ATREQ=$$.EncapsulatedATRequest.der
ATRESP=$$.EncapsulatedATResponse.der

echo "Génération de la ResponseDecryptionKey."
../PKIClient genkey --output $RESPDECRKEY

echo "Construction de la requête AT"
../PKIClient genATEnroll -c $ENROLMENTCERTIFICATE -k $ECVERIFICATIONKEY -d $RESPDECRKEY -v $ATVERIFICATIONKEY -p $AIDSSPLIST -R $EAID -K $EAENCRYPTIONPUBLICKEY -a $AAID -A $AAENCRYPTIONPUBLICKEY -o $ATREQ --taiutc $TAIUTC --debug

echo "Transmission de la requête à la AA"
curl -v -o $ATRESP --header "Content-type: application/x-its-request" --data-binary @$ATREQ $AASERVER

echo "Extraction de la réponse"
../PKIClient receiveATResponse --input $ATRESP --output $AUTHORIZATIONTICKET --responsedecryptionkey $RESPDECRKEY --aaverificationkey $AAVERIFICATIONPUBLICKEY --aaid $AAID --request $ATREQ --debug

echo "Suppression de la ResponseDecryptionKey"
rm $RESPDECRKEY

echo "Suppression des requête/réponse"
rm $ATREQ $ATRESP
