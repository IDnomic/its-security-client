
ifdef OPENSSL_HOME
	INCLUDEDIRS += -I $(OPENSSL_HOME)/include
	LDFLAGS += -L $(OPENSSL_HOME)
endif

CC = gcc

CFLAGS = -O0 -g -Wall $(INCLUDEDIRS)

LIBS = -lcrypto -ldl

PROGRAMS = PKIClient
ALLOBJS = utils.o ise_asn1.o isetoolbox.o genkey.o PKIClient.o receiveECResponse.o genECEnroll.o genATEnroll.o receiveATResponse.o

all : $(PROGRAMS)

clean:
	rm $(PROGRAMS) $(ALLOBJS)

.c.o :
	$(CC) -c $(CFLAGS) $(LDFLAGS) $<

PKIClient: PKIClient.o ise_asn1.o isetoolbox.o utils.o genkey.o receiveECResponse.o genECEnroll.o genATEnroll.o receiveATResponse.o
	$(CC) -o $@ $(LDFLAGS) $(LIBDIRS) $^ $(LIBS)

