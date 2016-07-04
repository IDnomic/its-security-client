#! /bin/sh

###### Bloc de configuration

### Paramètres propres au boitier ITS

TECHNICALKEY=TechnicalKey

######


# Clé technique, ne bouge pas de la vie de l'ITS
if [ ! -f $TECHNICALKEY ]; then
  echo "Génération de la clé technique."
  ../PKIClient genkey --output $TECHNICALKEY
fi

