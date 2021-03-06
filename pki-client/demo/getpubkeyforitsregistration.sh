#! /bin/sh

KEYFILE=$1

if [ -z $KEYFILE ]; then
  echo "File name required."
  exit
fi

openssl ec -in $KEYFILE -pubout -outform D 2> /dev/null | od -t x1 -A n | sed 's/ //g' | tr 'a-f' 'A-F' | awk '{ printf("%s", $0); }'

