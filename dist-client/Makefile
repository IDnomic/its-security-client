# Pour MacOSX
INCLUDEDIRS = -I /opt/local/include
LIBDIRS = -L /opt/local/lib

CC = gcc

#CFLAGS = -O2
CFLAGS = -O0 -g -Wall $(INCLUDEDIRS)

#LDFLAGS = -Bstatic

#STATIC = yes

ifeq ($(STATIC),yes)
  LIBS = /opt/local/lib/libcrypto.a /opt/local/lib/libz.a -ldl
else
  LIBS = -lcrypto -ldl
endif

PROGRAMS = PKIClient
ALLOBJS = utils.o ise_asn1.o isetoolbox.o genkey.o PKIClient.o receiveECResponse.o genECEnroll.o genATEnroll.o receiveATResponse.o

all : $(PROGRAMS)

clean:
	rm $(PROGRAMS) $(ALLOBJS)

.c.o :
	$(CC) -c $(CFLAGS) $(LDFLAGS) $<

PKIClient: PKIClient.o ise_asn1.o isetoolbox.o utils.o genkey.o receiveECResponse.o genECEnroll.o genATEnroll.o receiveATResponse.o
	$(CC) -o $@ $(LDFLAGS) $(LIBDIRS) $^ $(LIBS)

