#! /bin/sh

###### Configuration bloc

### ITS parameters

TECHNICALKEY=TechnicalKey

######


# Technical key.
if [ ! -f $TECHNICALKEY ]; then
  echo "Technical key generation."
  ../PKIClient genkey --output $TECHNICALKEY
fi

