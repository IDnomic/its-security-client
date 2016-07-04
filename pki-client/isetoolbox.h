#pragma once

#include <openssl/ec.h>
#include "ise_asn1.h"

unsigned char *ISE_PUBLICKEY_HashedId8(EC_KEY *key);

ASN1_OCTET_STRING *findsignedmessagedigest(STACK_OF(X509_ALGOR) *signedAttributes);
ASN1_OBJECT *findsignedcontenttype(STACK_OF(X509_ALGOR) *signedAttributes);

int ASN1_OBJECT_cmp(ASN1_OBJECT *o1, ASN1_OBJECT *o2);

ISE_INNERECREQUEST *buildInnerECRequest(char *canonicalId,
                                        unsigned char *wantedSubjectAttributes, int attributeslen,
                                        unsigned char *wantedValidityRestrictions, int restrictionslen,
                                        EC_KEY *responseDecryptionKey);

ISE_SIGNEDDATA *buildSignedData(ASN1_OBJECT *signedContentType, databuf *payload, int detached);
int signSignedData(ISE_SIGNEDDATA *signedData, databuf *payload, unsigned char *signerId, EC_KEY *key, int taiutc, int addhashalg);
int verifySignerInfoSignature(ISE_SIGNERINFO *si, EC_KEY *key);
int verifySignedData(ISE_SIGNEDDATA *signedData, unsigned char *signerid, EC_KEY *key);

ISE_RECIPIENTINFO *encryptECIES(unsigned char *recipientId, unsigned char *aeskey, EC_KEY *recipientKey);
int decryptECIES(unsigned char *myHashedId8, unsigned char *aeskey, EC_KEY *key, STACK_OF(ISE_RECIPIENTINFO) *recipientInfos);

int genSecretAESCCMParameters(unsigned char **aeskey, unsigned char **aesccmnonce);

ISE_ENCRYPTEDDATA *buildEncryptedData(ASN1_OBJECT *encryptedContentType, databuf *payload, unsigned char *aesccmnonce);
int addEncryptedDataRecipient(ISE_ENCRYPTEDDATA *encryptedData, unsigned char *recipientId, unsigned char *aeskey, EC_KEY *key);
int decrypt_ISE_ENCRYPTEDDATA(ISE_ENCRYPTEDDATA *encryptedData, unsigned char *myid, EC_KEY *mykey, databuf **output);

ISE_DATA *buildData(ASN1_OBJECT *contentType, databuf *payload);

ISE_SHAREDATREQUEST *buildSharedATRequest(unsigned char *eaId, unsigned char *keyTag,
                                          unsigned char *wantedSubjectAttributes, int attributeslen,
                                          unsigned char *wantedValidityRestrictions, int restrictionslen,
                                          long wantedStart, EC_KEY *responseDecryptionKey);

ISE_INNERATREQUEST *buildInnerATRequest(ISE_PUBLICKEY *verificationkey, ISE_PUBLICKEY *encryptionkey,
                                        unsigned char *hmackey, ISE_SHAREDATREQUEST *sharedATreq,
                                        ISE_ENCRYPTEDDATA *detachedEncryptedSignature);
