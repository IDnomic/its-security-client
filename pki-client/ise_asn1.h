#pragma once

#include <openssl/opensslconf.h>
#include <openssl/symhacks.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/stack.h>
#include <openssl/asn1.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>


#define ASN1_OBJECT_dup(x) ASN1_dup_of(ASN1_OBJECT,i2d_ASN1_OBJECT,d2i_ASN1_OBJECT,x)

#define DECLARE_ASN1_DUP_FUNCTION(stname) stname * stname##_dup(stname *x);

//int NID_OpenTrust;
//int NID_OT_Innovation;
//int NID_OT_Innovation_ISE;
int NID_ISE_ct;
int NID_ISE_ct_Data;
int NID_ISE_ct_SignedData;
int NID_ISE_ct_EncryptedData;
int NID_ISE_ct_EnrolmentRequest;
int NID_ISE_ct_EnrolmentResponse;
int NID_ISE_ct_AuthorizationRequest;
int NID_ISE_ct_AuthorizationResponse;
int NID_ISE_ct_AuthorizationValidationRequest;
int NID_ISE_ct_AuthorizationValidationResponse;
int NID_ISE_ct_SharedATRequest;
int NID_ISE_algos;
int NID_ISE_algos_aes128CCM_103097;
int NID_ISE_algos_ecies_103097;
int NID_ISE_attrs;
int NID_ISE_attrs_messageDigest;
int NID_ISE_attrs_contentType;
int NID_ISE_attrs_signingTime;

void addISEoids(void);


/*
 * PublicKey ::= SEQUENCE {
 *   type ECCPublicKeyType,
 *   x INTEGER }
 */

typedef struct {
    ASN1_ENUMERATED *type;
    ASN1_INTEGER *x;
} ISE_PUBLICKEY;

DECLARE_ASN1_FUNCTIONS(ISE_PUBLICKEY);
DECLARE_ASN1_DUP_FUNCTION(ISE_PUBLICKEY);
DECLARE_ASN1_PRINT_FUNCTION(ISE_PUBLICKEY);
#define d2i_ISE_PUBLICKEY_bio(bp,p) ASN1_d2i_bio_of(ISE_PUBLICKEY,ISE_PUBLICKEY_new,d2i_ISE_PUBLICKEY,bp,p)
#define i2d_ISE_PUBLICKEY_bio(bp,o) ASN1_i2d_bio_of(ISE_PUBLICKEY,i2d_ISE_PUBLICKEY,bp,o)
#define d2i_ISE_PUBLICKEY_fp(fp,p) ASN1_d2i_fp_of(ISE_PUBLICKEY,ISE_PUBLICKEY_new,d2i_ISE_PUBLICKEY,fp,p)
#define i2d_ISE_PUBLICKEY_fp(fp,p) ASN1_i2d_fp_of(ISE_PUBLICKEY,i2d_ISE_PUBLICKEY,fp,p)
ISE_PUBLICKEY *ISE_PUBLICKEY_set(ISE_PUBLICKEY **a, EC_KEY *key);
EC_KEY *ISE_PUBLICKEY_to_EC_KEY(EC_KEY **a, ISE_PUBLICKEY *key);

#define COMPRESSED_Y_LSB0 2
#define COMPRESSED_Y_LSB1 3


/*
 * ECIESEncryptedKey103097 ::= SEQUENCE {
 * 	v PublicKey,
 *	c OCTET STRING (SIZE(16)),
 *	t OCTET STRING (SIZE(16)) }
 */

typedef struct {
    ISE_PUBLICKEY *v;
    ASN1_OCTET_STRING *c;
    ASN1_OCTET_STRING *t;
} ISE_ECIESENCRYPTEDKEY103097;

DECLARE_ASN1_FUNCTIONS(ISE_ECIESENCRYPTEDKEY103097);
DECLARE_ASN1_DUP_FUNCTION(ISE_ECIESENCRYPTEDKEY103097);
DECLARE_ASN1_PRINT_FUNCTION(ISE_ECIESENCRYPTEDKEY103097);
#define d2i_ISE_ECIESENCRYPTEDKEY103097_bio(bp,p) ASN1_d2i_bio_of(ISE_ECIESENCRYPTEDKEY103097,ISE_ECIESENCRYPTEDKEY103097_new,d2i_ISE_ECIESENCRYPTEDKEY103097,bp,p)
#define i2d_ISE_ECIESENCRYPTEDKEY103097_bio(bp,o) ASN1_i2d_bio_of(ISE_ECIESENCRYPTEDKEY103097,i2d_ISE_ECIESENCRYPTEDKEY103097,bp,o)
#define d2i_ISE_ECIESENCRYPTEDKEY103097_fp(fp,p) ASN1_d2i_fp_of(ISE_ECIESENCRYPTEDKEY103097,ISE_ECIESENCRYPTEDKEY103097_new,d2i_ISE_ECIESENCRYPTEDKEY103097,fp,p)
#define i2d_ISE_ECIESENCRYPTEDKEY103097_fp(fp,p) ASN1_i2d_fp_of(ISE_ECIESENCRYPTEDKEY103097,i2d_ISE_ECIESENCRYPTEDKEY103097,fp,p)


/*
 * Data ::= SEQUENCE {
 *   version Version DEFAULT v1,
 *   contentType ContentType,
 *   content OCTET STRING OPTIONAL }
 */

typedef struct {
    ASN1_INTEGER *version;
    ASN1_OBJECT *contentType;
    ASN1_OCTET_STRING *content;
} ISE_DATA;

DECLARE_ASN1_FUNCTIONS(ISE_DATA);
DECLARE_ASN1_DUP_FUNCTION(ISE_DATA);
DECLARE_ASN1_PRINT_FUNCTION(ISE_DATA);
#define d2i_ISE_DATA_bio(bp,p) ASN1_d2i_bio_of(ISE_DATA,ISE_DATA_new,d2i_ISE_DATA,bp,p)
#define i2d_ISE_DATA_bio(bp,o) ASN1_i2d_bio_of(ISE_DATA,i2d_ISE_DATA,bp,o)
#define d2i_ISE_DATA_fp(fp,p) ASN1_d2i_fp_of(ISE_DATA,ISE_DATA_new,d2i_ISE_DATA,fp,p)
#define i2d_ISE_DATA_fp(fp,p) ASN1_i2d_fp_of(ISE_DATA,i2d_ISE_DATA,fp,p)

/*
 * RecipientInfo ::= SEQUENCE {
 *   recipient HashedId8,
 *   kexalgid KeyEncryptionAlgorithmIdentifier DEFAULT { algorithm id-ecies-103097 },
 *   encryptedKeyMaterial OCTET STRING }
 */

typedef struct {
    ASN1_OCTET_STRING *recipient;
    X509_ALGOR *kexalgid;
    ASN1_OCTET_STRING *encryptedKeyMaterial;
} ISE_RECIPIENTINFO;

DECLARE_ASN1_FUNCTIONS(ISE_RECIPIENTINFO);
DECLARE_ASN1_DUP_FUNCTION(ISE_RECIPIENTINFO);
DECLARE_ASN1_PRINT_FUNCTION(ISE_RECIPIENTINFO);
#define d2i_ISE_RECIPIENTINFO_bio(bp,p) ASN1_d2i_bio_of(ISE_RECIPIENTINFO,ISE_RECIPIENTINFO_new,d2i_ISE_RECIPIENTINFO,bp,p)
#define i2d_ISE_RECIPIENTINFO_bio(bp,o) ASN1_i2d_bio_of(ISE_RECIPIENTINFO,i2d_ISE_RECIPIENTINFO,bp,o)
#define d2i_ISE_RECIPIENTINFO_fp(fp,p) ASN1_d2i_fp_of(ISE_RECIPIENTINFO,ISE_RECIPIENTINFO_new,d2i_ISE_RECIPIENTINFO,fp,p)
#define i2d_ISE_RECIPIENTINFO_fp(fp,p) ASN1_i2d_fp_of(ISE_RECIPIENTINFO,i2d_ISE_RECIPIENTINFO,fp,p)

DECLARE_STACK_OF(ISE_RECIPIENTINFO);

/* allocate & free */
#define sk_ISE_RECIPIENTINFO_new(cmp)                 SKM_sk_new(ISE_RECIPIENTINFO, (cmp))
#define sk_ISE_RECIPIENTINFO_new_null()               SKM_sk_new_null(ISE_RECIPIENTINFO)
#define sk_ISE_RECIPIENTINFO_free(st)                 SKM_sk_free(ISE_RECIPIENTINFO, (st))
#define sk_ISE_RECIPIENTINFO_pop_free(st, free_func)  SKM_sk_pop_free(ISE_RECIPIENTINFO, (st), (free_func))
#define sk_ISE_RECIPIENTINFO_dup(st)                  SKM_sk_dup(ISE_RECIPIENTINFO, st)

/* get & set */
#define sk_ISE_RECIPIENTINFO_num(st)                  SKM_sk_num(ISE_RECIPIENTINFO, (st))
#define sk_ISE_RECIPIENTINFO_value(st, i)             SKM_sk_value(ISE_RECIPIENTINFO, (st), (i))
#define sk_ISE_RECIPIENTINFO_set(st, i, val)          SKM_sk_set(ISE_RECIPIENTINFO, (st), (i), (val))

/* add value */
#define sk_ISE_RECIPIENTINFO_insert(st, val, i)       SKM_sk_insert(ISE_RECIPIENTINFO, (st), (val), (i))
#define sk_ISE_RECIPIENTINFO_push(st, val)            SKM_sk_push(ISE_RECIPIENTINFO, (st), (val))
#define sk_ISE_RECIPIENTINFO_unshift(st, val)         SKM_sk_unshift(ISE_RECIPIENTINFO, (st), (val))

/* sort & find */
#define sk_ISE_RECIPIENTINFO_set_cmp_func(st, cmp)    SKM_sk_set_cmp_func(ISE_RECIPIENTINFO, (st), (cmp))
#define sk_ISE_RECIPIENTINFO_sort(st)                 SKM_sk_sort(ISE_RECIPIENTINFO, (st))
#define sk_ISE_RECIPIENTINFO_is_sorted(st)            SKM_sk_is_sorted(ISE_RECIPIENTINFO, (st))
#define sk_ISE_RECIPIENTINFO_find(st, val)            SKM_sk_find(ISE_RECIPIENTINFO, (st), (val))
#define sk_ISE_RECIPIENTINFO_find_ex(st, val)         SKM_sk_find_ex(ISE_RECIPIENTINFO, (st), (val))

/* delete value */
#define sk_ISE_RECIPIENTINFO_delete(st, i)            SKM_sk_delete(ISE_RECIPIENTINFO, (st), (i))
#define sk_ISE_RECIPIENTINFO_delete_ptr(st, ptr)      SKM_sk_delete_ptr(ISE_RECIPIENTINFO, (st), (ptr))
#define sk_ISE_RECIPIENTINFO_pop(st)                  SKM_sk_pop(ISE_RECIPIENTINFO, (st))
#define sk_ISE_RECIPIENTINFO_shift(st)                SKM_sk_shift(ISE_RECIPIENTINFO, (st))
#define sk_ISE_RECIPIENTINFO_zero(st)                 SKM_sk_zero(ISE_RECIPIENTINFO, (st))


/*
 * CCMDefaultParameters ::= SEQUENCE {
 *   aes-nonce OCTET STRING (SIZE(12)) }
 */

typedef struct {
    ASN1_OCTET_STRING *aesNonce;
} ISE_CCMDEFAULTPARAMETERS;

DECLARE_ASN1_FUNCTIONS(ISE_CCMDEFAULTPARAMETERS);
DECLARE_ASN1_DUP_FUNCTION(ISE_CCMDEFAULTPARAMETERS);
DECLARE_ASN1_PRINT_FUNCTION(ISE_CCMDEFAULTPARAMETERS);
#define d2i_ISE_CCMDEFAULTPARAMETERS_bio(bp,p) ASN1_d2i_bio_of(ISE_CCMDEFAULTPARAMETERS,ISE_CCMDEFAULTPARAMETERS_new,d2i_ISE_CCMDEFAULTPARAMETERS,bp,p)
#define i2d_ISE_CCMDEFAULTPARAMETERS_bio(bp,o) ASN1_i2d_bio_of(ISE_CCMDEFAULTPARAMETERS,i2d_ISE_CCMDEFAULTPARAMETERS,bp,o)
#define d2i_ISE_CCMDEFAULTPARAMETERS_fp(fp,p) ASN1_d2i_fp_of(ISE_CCMDEFAULTPARAMETERS,ISE_CCMDEFAULTPARAMETERS_new,d2i_ISE_CCMDEFAULTPARAMETERS,fp,p)
#define i2d_ISE_CCMDEFAULTPARAMETERS_fp(fp,p) ASN1_i2d_fp_of(ISE_CCMDEFAULTPARAMETERS,i2d_ISE_CCMDEFAULTPARAMETERS,fp,p)


/*
 * EncryptedData ::= SEQUENCE {
 *   version Version DEFAULT v1,
 *   recipients RecipientInfos,
 *   encryptedContentType ContentType,
 *   encryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *   encryptedContent OCTET STRING OPTIONAL }
 */

typedef struct {
    ASN1_INTEGER *version;
    STACK_OF(ISE_RECIPIENTINFO) *recipientInfos;
    ASN1_OBJECT *encryptedContentType;
    X509_ALGOR *encryptionAlgorithm;
    ASN1_OCTET_STRING *encryptedContent;
} ISE_ENCRYPTEDDATA;

DECLARE_ASN1_FUNCTIONS(ISE_ENCRYPTEDDATA);
DECLARE_ASN1_DUP_FUNCTION(ISE_ENCRYPTEDDATA);
DECLARE_ASN1_PRINT_FUNCTION(ISE_ENCRYPTEDDATA);
#define d2i_ISE_ENCRYPTEDDATA_bio(bp,p) ASN1_d2i_bio_of(ISE_ENCRYPTEDDATA,ISE_ENCRYPTEDDATA_new,d2i_ISE_ENCRYPTEDDATA,bp,p)
#define i2d_ISE_ENCRYPTEDDATA_bio(bp,o) ASN1_i2d_bio_of(ISE_ENCRYPTEDDATA,i2d_ISE_ENCRYPTEDDATA,bp,o)
#define d2i_ISE_ENCRYPTEDDATA_fp(fp,p) ASN1_d2i_fp_of(ISE_ENCRYPTEDDATA,ISE_ENCRYPTEDDATA_new,d2i_ISE_ENCRYPTEDDATA,fp,p)
#define i2d_ISE_ENCRYPTEDDATA_fp(fp,p) ASN1_i2d_fp_of(ISE_ENCRYPTEDDATA,i2d_ISE_ENCRYPTEDDATA,fp,p)


/*
 * CertificateDigest ::= SEQUENCE {
 *   algorithm HashAlgorithmIdentifier DEFAULT { algorithm id-sha256 },
 *   digest HashedId8 }
 */

typedef struct {
    X509_ALGOR *algorithm;
    ASN1_OCTET_STRING *digest;
} ISE_CERTIFICATEDIGEST;

DECLARE_ASN1_FUNCTIONS(ISE_CERTIFICATEDIGEST);
DECLARE_ASN1_DUP_FUNCTION(ISE_CERTIFICATEDIGEST);
DECLARE_ASN1_PRINT_FUNCTION(ISE_CERTIFICATEDIGEST);
#define d2i_ISE_CERTIFICATEDIGEST_bio(bp,p) ASN1_d2i_bio_of(ISE_CERTIFICATEDIGEST,ISE_CERTIFICATEDIGEST_new,d2i_ISE_CERTIFICATEDIGEST,bp,p)
#define i2d_ISE_CERTIFICATEDIGEST_bio(bp,o) ASN1_i2d_bio_of(ISE_CERTIFICATEDIGEST,i2d_ISE_CERTIFICATEDIGEST,bp,o)
#define d2i_ISE_CERTIFICATEDIGEST_fp(fp,p) ASN1_d2i_fp_of(ISE_CERTIFICATEDIGEST,ISE_CERTIFICATEDIGEST_new,d2i_ISE_CERTIFICATEDIGEST,fp,p)
#define i2d_ISE_CERTIFICATEDIGEST_fp(fp,p) ASN1_i2d_fp_of(ISE_CERTIFICATEDIGEST,i2d_ISE_CERTIFICATEDIGEST,fp,p)


/*
 * SignerIdentifier ::= CHOICE {
 *   self NULL,
 *   certificateDigest CertificateDigest,
 *   certificate Certificate }
 */

typedef struct {
    int type;
    union {
        ASN1_NULL *null;
        ISE_CERTIFICATEDIGEST *certificateDigest;
        ASN1_OCTET_STRING *certificate;
    } value;
} ISE_SIGNERIDENTIFIER;

DECLARE_ASN1_FUNCTIONS(ISE_SIGNERIDENTIFIER);
DECLARE_ASN1_DUP_FUNCTION(ISE_SIGNERIDENTIFIER);
DECLARE_ASN1_PRINT_FUNCTION(ISE_SIGNERIDENTIFIER);
#define d2i_ISE_SIGNERIDENTIFIER_bio(bp,p) ASN1_d2i_bio_of(ISE_SIGNERIDENTIFIER,ISE_SIGNERIDENTIFIER_new,d2i_ISE_SIGNERIDENTIFIER,bp,p)
#define i2d_ISE_SIGNERIDENTIFIER_bio(bp,o) ASN1_i2d_bio_of(ISE_SIGNERIDENTIFIER,i2d_ISE_SIGNERIDENTIFIER,bp,o)
#define d2i_ISE_SIGNERIDENTIFIER_fp(fp,p) ASN1_d2i_fp_of(ISE_SIGNERIDENTIFIER,ISE_SIGNERIDENTIFIER_new,d2i_ISE_SIGNERIDENTIFIER,fp,p)
#define i2d_ISE_SIGNERIDENTIFIER_fp(fp,p) ASN1_i2d_fp_of(ISE_SIGNERIDENTIFIER,i2d_ISE_SIGNERIDENTIFIER,fp,p)


/*
 * SignerInfo ::= SEQUENCE {
 *   version Version DEFAULT v1,
 *   signer [0] SignerIdentifier DEFAULT self:NULL,
 *   digestAlgorithm [1] HashAlgorithmIdentifier DEFAULT { algorithm id-sha256 },
 *   signatureAlgorithm [2] SignatureAlgorithmIdentifier DEFAULT { algorithm ecdsa-with-SHA256 },
 *   signedAttributes SignedAttributes,
 *   certificateChain SEQUENCE OF Certificate OPTIONAL,
 *   signature SignatureValue }
 */

typedef struct {
    ASN1_INTEGER *version;
    ISE_SIGNERIDENTIFIER *signer;
    X509_ALGOR *digestAlgorithm;
    X509_ALGOR *signatureAlgorithm;
    STACK_OF(X509_ALGOR) *signedAttributes;
    STACK_OF(ASN1_OCTET_STRING) *certificateChain;
    ASN1_OCTET_STRING *signature;
} ISE_SIGNERINFO;

DECLARE_ASN1_FUNCTIONS(ISE_SIGNERINFO);
DECLARE_ASN1_DUP_FUNCTION(ISE_SIGNERINFO);
DECLARE_ASN1_PRINT_FUNCTION(ISE_SIGNERINFO);
#define d2i_ISE_SIGNERINFO_bio(bp,p) ASN1_d2i_bio_of(ISE_SIGNERINFO,ISE_SIGNERINFO_new,d2i_ISE_SIGNERINFO,bp,p)
#define i2d_ISE_SIGNERINFO_bio(bp,o) ASN1_i2d_bio_of(ISE_SIGNERINFO,i2d_ISE_SIGNERINFO,bp,o)
#define d2i_ISE_SIGNERINFO_fp(fp,p) ASN1_d2i_fp_of(ISE_SIGNERINFO,ISE_SIGNERINFO_new,d2i_ISE_SIGNERINFO,fp,p)
#define i2d_ISE_SIGNERINFO_fp(fp,p) ASN1_i2d_fp_of(ISE_SIGNERINFO,i2d_ISE_SIGNERINFO,fp,p)

DECLARE_ASN1_ITEM(ISE_SIGNEDDATA_ATTRIBUTES_SIGN)

    DECLARE_STACK_OF(ISE_SIGNERINFO);

    /* allocate & free */
#define sk_ISE_SIGNERINFO_new(cmp)                 SKM_sk_new(ISE_SIGNERINFO, (cmp))
#define sk_ISE_SIGNERINFO_new_null()               SKM_sk_new_null(ISE_SIGNERINFO)
#define sk_ISE_SIGNERINFO_free(st)                 SKM_sk_free(ISE_SIGNERINFO, (st))
#define sk_ISE_SIGNERINFO_pop_free(st, free_func)  SKM_sk_pop_free(ISE_SIGNERINFO, (st), (free_func))
#define sk_ISE_SIGNERINFO_dup(st)                  SKM_sk_dup(ISE_SIGNERINFO, st)

    /* get & set */
#define sk_ISE_SIGNERINFO_num(st)                  SKM_sk_num(ISE_SIGNERINFO, (st))
#define sk_ISE_SIGNERINFO_value(st, i)             SKM_sk_value(ISE_SIGNERINFO, (st), (i))
#define sk_ISE_SIGNERINFO_set(st, i, val)          SKM_sk_set(ISE_SIGNERINFO, (st), (i), (val))

    /* add value */
#define sk_ISE_SIGNERINFO_insert(st, val, i)       SKM_sk_insert(ISE_SIGNERINFO, (st), (val), (i))
#define sk_ISE_SIGNERINFO_push(st, val)            SKM_sk_push(ISE_SIGNERINFO, (st), (val))
#define sk_ISE_SIGNERINFO_unshift(st, val)         SKM_sk_unshift(ISE_SIGNERINFO, (st), (val))

    /* sort & find */
#define sk_ISE_SIGNERINFO_set_cmp_func(st, cmp)    SKM_sk_set_cmp_func(ISE_SIGNERINFO, (st), (cmp))
#define sk_ISE_SIGNERINFO_sort(st)                 SKM_sk_sort(ISE_SIGNERINFO, (st))
#define sk_ISE_SIGNERINFO_is_sorted(st)            SKM_sk_is_sorted(ISE_SIGNERINFO, (st))
#define sk_ISE_SIGNERINFO_find(st, val)            SKM_sk_find(ISE_SIGNERINFO, (st), (val))
#define sk_ISE_SIGNERINFO_find_ex(st, val)         SKM_sk_find_ex(ISE_SIGNERINFO, (st), (val))

    /* delete value */
#define sk_ISE_SIGNERINFO_delete(st, i)            SKM_sk_delete(ISE_SIGNERINFO, (st), (i))
#define sk_ISE_SIGNERINFO_delete_ptr(st, ptr)      SKM_sk_delete_ptr(ISE_SIGNERINFO, (st), (ptr))
#define sk_ISE_SIGNERINFO_pop(st)                  SKM_sk_pop(ISE_SIGNERINFO, (st))
#define sk_ISE_SIGNERINFO_shift(st)                SKM_sk_shift(ISE_SIGNERINFO, (st))
#define sk_ISE_SIGNERINFO_zero(st)                 SKM_sk_zero(ISE_SIGNERINFO, (st))


    /*
     * SignedData ::= SEQUENCE {
     *   version Version DEFAULT v1,
     *   hashAlgorithms HashAlgorithmsIdentifiers,
     *   signedContentType ContentType,
     *   signedContent OCTET STRING OPTIONAL,
     *   signerInfos SignerInfos }
     */

    typedef struct {
        ASN1_INTEGER *version;
        STACK_OF(X509_ALGOR) *hashAlgorithms;
        ASN1_OBJECT *signedContentType;
        ASN1_OCTET_STRING *signedContent;
        STACK_OF(ISE_SIGNERINFO) *signerInfos;
    } ISE_SIGNEDDATA;

DECLARE_ASN1_FUNCTIONS(ISE_SIGNEDDATA);
DECLARE_ASN1_DUP_FUNCTION(ISE_SIGNEDDATA);
DECLARE_ASN1_PRINT_FUNCTION(ISE_SIGNEDDATA);
#define d2i_ISE_SIGNEDDATA_bio(bp,p) ASN1_d2i_bio_of(ISE_SIGNEDDATA,ISE_SIGNEDDATA_new,d2i_ISE_SIGNEDDATA,bp,p)
#define i2d_ISE_SIGNEDDATA_bio(bp,o) ASN1_i2d_bio_of(ISE_SIGNEDDATA,i2d_ISE_SIGNEDDATA,bp,o)
#define d2i_ISE_SIGNEDDATA_fp(fp,p) ASN1_d2i_fp_of(ISE_SIGNEDDATA,ISE_SIGNEDDATA_new,d2i_ISE_SIGNEDDATA,fp,p)
#define i2d_ISE_SIGNEDDATA_fp(fp,p) ASN1_i2d_fp_of(ISE_SIGNEDDATA,i2d_ISE_SIGNEDDATA,fp,p)


/*
 * InnerECRequest ::= SEQUENCE {
 *   requestIdentifier OCTET STRING (SIZE(16)),
 *   itsId IA5String,
 *   wantedSubjectAttributes SubjectAttributes,
 *   wantedValidityRestrictions ValidityRestrictions OPTIONAL,
 *   responseEncryptionKey PublicKey }
 */

typedef struct {
    ASN1_OCTET_STRING *requestIdentifier;
    ASN1_IA5STRING *itsId;
    ASN1_OCTET_STRING *wantedSubjectAttributes;
    ASN1_OCTET_STRING *wantedValidityRestrictions;
    ISE_PUBLICKEY *responseEncryptionKey;
} ISE_INNERECREQUEST;

DECLARE_ASN1_FUNCTIONS(ISE_INNERECREQUEST);
DECLARE_ASN1_DUP_FUNCTION(ISE_INNERECREQUEST);
DECLARE_ASN1_PRINT_FUNCTION(ISE_INNERECREQUEST);
#define d2i_ISE_INNERECREQUEST_bio(bp,p) ASN1_d2i_bio_of(ISE_INNERECREQUEST,ISE_INNERECREQUEST_new,d2i_ISE_INNERECREQUEST,bp,p)
#define i2d_ISE_INNERECREQUEST_bio(bp,o) ASN1_i2d_bio_of(ISE_INNERECREQUEST,i2d_ISE_INNERECREQUEST,bp,o)
#define d2i_ISE_INNERECREQUEST_fp(fp,p) ASN1_d2i_fp_of(ISE_INNERECREQUEST,ISE_INNERECREQUEST_new,d2i_ISE_INNERECREQUEST,fp,p)
#define i2d_ISE_INNERECREQUEST_fp(fp,p) ASN1_i2d_fp_of(ISE_INNERECREQUEST,i2d_ISE_INNERECREQUEST,fp,p)


/*
 * InnerECResponse ::= SEQUENCE {
 *   requestHash OCTET STRING (SIZE(16)),
 *   responseCode EnrolmentResponseCode,
 *   certificate Certificate OPTIONAL,
 *   cAContributionValue INTEGER OPTIONAL }
 */

typedef struct {
    ASN1_OCTET_STRING *requestHash;
    ASN1_ENUMERATED *responseCode;
    ASN1_OCTET_STRING *certificate;
    ASN1_INTEGER *cAContributionValue;
} ISE_INNERECRESPONSE;

DECLARE_ASN1_FUNCTIONS(ISE_INNERECRESPONSE);
DECLARE_ASN1_DUP_FUNCTION(ISE_INNERECRESPONSE);
DECLARE_ASN1_PRINT_FUNCTION(ISE_INNERECRESPONSE);
#define d2i_ISE_INNERECRESPONSE_bio(bp,p) ASN1_d2i_bio_of(ISE_INNERECRESPONSE,ISE_INNERECRESPONSE_new,d2i_ISE_INNERECRESPONSE,bp,p)
#define i2d_ISE_INNERECRESPONSE_bio(bp,o) ASN1_i2d_bio_of(ISE_INNERECRESPONSE,i2d_ISE_INNERECRESPONSE,bp,o)
#define d2i_ISE_INNERECRESPONSE_fp(fp,p) ASN1_d2i_fp_of(ISE_INNERECRESPONSE,ISE_INNERECRESPONSE_new,d2i_ISE_INNERECRESPONSE,fp,p)
#define i2d_ISE_INNERECRESPONSE_fp(fp,p) ASN1_i2d_fp_of(ISE_INNERECRESPONSE,i2d_ISE_INNERECRESPONSE,fp,p)

#define ISE_ECRC_OK                          0
#define ISE_ECRC_CANTPARSE                   1 // valid for any structure
#define ISE_ECRC_BADCONTENTTYPE              2 // not encrypted, not signed, not enrolmentrequest
#define ISE_ECRC_IMNOTTHERECIPIENT           3 // the "recipients" doesn't include me
#define ISE_ECRC_UNKNOWNENCRYPTIONALGORITHM  4 // either kexalg or contentencryptionalgorithm
#define ISE_ECRC_DECRYPTIONFAILED            5 // works for ECIES-HMAC and AES-CCM
#define ISE_ECRC_UNKNOWNITS                  6 // can't retrieve the ITS from the itsId
#define ISE_ECRC_INVALIDSIGNATURE            7 // signature verification of the request fails
#define ISE_ECRC_INVALIDENCRYPTIONKEY        8 // signature is good, but the responseEncryptionKey is bad
#define ISE_ECRC_BADITSSTATUS                9 // revoked, not yet active
#define ISE_ECRC_INCOMPLETEREQUEST          10 // some elements are missing
#define ISE_ECRC_DENIEDPERMISSIONS          11 // requested permissions are not granted
#define ISE_ECRC_INVALISKEYS                12 // either the verification_key of the encryption_key is bad
#define ISE_ECRC_DENIEDREQUEST              13 // any other reason?


/*
 * SharedATRequest ::= SEQUENCE {
 *   requestIdentifier OCTET STRING (SIZE(16)),
 *   eaId HashedId8,
 *   keyTag OCTET STRING (SIZE(16)),
 *   wantedSubjectAttributes SubjectAttributes,
 *   wantedValidityRestrictions ValidityRestrictions OPTIONAL,
 *   wantedStart Time32,
 *   responseEncryptionKey PublicKey }
 */

typedef struct {
    ASN1_OCTET_STRING *requestIdentifier;
    ASN1_OCTET_STRING *eaId;
    ASN1_OCTET_STRING *keyTag;
    ASN1_OCTET_STRING *wantedSubjectAttributes;
    ASN1_OCTET_STRING *wantedValidityRestrictions;
    ASN1_INTEGER *wantedStart;
    ISE_PUBLICKEY *responseEncryptionKey;
} ISE_SHAREDATREQUEST;

DECLARE_ASN1_FUNCTIONS(ISE_SHAREDATREQUEST);
DECLARE_ASN1_DUP_FUNCTION(ISE_SHAREDATREQUEST);
DECLARE_ASN1_PRINT_FUNCTION(ISE_SHAREDATREQUEST);
#define d2i_ISE_SHAREDATREQUEST_bio(bp,p) ASN1_d2i_bio_of(ISE_SHAREDATREQUEST,ISE_SHAREDATREQUEST_new,d2i_ISE_SHAREDATREQUEST,bp,p)
#define i2d_ISE_SHAREDATREQUEST_bio(bp,o) ASN1_i2d_bio_of(ISE_SHAREDATREQUEST,i2d_ISE_SHAREDATREQUEST,bp,o)
#define d2i_ISE_SHAREDATREQUEST_fp(fp,p) ASN1_d2i_fp_of(ISE_SHAREDATREQUEST,ISE_SHAREDATREQUEST_new,d2i_ISE_SHAREDATREQUEST,fp,p)
#define i2d_ISE_SHAREDATREQUEST_fp(fp,p) ASN1_i2d_fp_of(ISE_SHAREDATREQUEST,i2d_ISE_SHAREDATREQUEST,fp,p)


/*
 * InnerATRequest ::= SEQUENCE {
 *   verificationKey PublicKey,
 *   encryptionKey PublicKey OPTIONAL,
 *   hmacKey OCTET STRING (SIZE(32)),
 *   signedByEC SharedATRequest,
 *   detachedEncryptedSignature EncryptedData }
 */

typedef struct {
    ISE_PUBLICKEY *verificationKey;
    ISE_PUBLICKEY *encryptionKey;
    ASN1_OCTET_STRING *hmacKey;
    ISE_SHAREDATREQUEST *signedByEC;
    ISE_ENCRYPTEDDATA *detachedEncryptedSignature;
} ISE_INNERATREQUEST;

DECLARE_ASN1_FUNCTIONS(ISE_INNERATREQUEST);
DECLARE_ASN1_DUP_FUNCTION(ISE_INNERATREQUEST);
DECLARE_ASN1_PRINT_FUNCTION(ISE_INNERATREQUEST);
#define d2i_ISE_INNERATREQUEST_bio(bp,p) ASN1_d2i_bio_of(ISE_INNERATREQUEST,ISE_INNERATREQUEST_new,d2i_ISE_INNERATREQUEST,bp,p)
#define i2d_ISE_INNERATREQUEST_bio(bp,o) ASN1_i2d_bio_of(ISE_INNERATREQUEST,i2d_ISE_INNERATREQUEST,bp,o)
#define d2i_ISE_INNERATREQUEST_fp(fp,p) ASN1_d2i_fp_of(ISE_INNERATREQUEST,ISE_INNERATREQUEST_new,d2i_ISE_INNERATREQUEST,fp,p)
#define i2d_ISE_INNERATREQUEST_fp(fp,p) ASN1_i2d_fp_of(ISE_INNERATREQUEST,i2d_ISE_INNERATREQUEST,fp,p)


/*
 * InnerATResponse ::= SEQUENCE {
 *   requestHash OCTET STRING (SIZE(16)),
 *   responseCode AuthorizationResponseCode,
 *   certificate Certificate OPTIONAL,
 *   cAContributionValue INTEGER OPTIONAL }
 */

typedef struct {
    ASN1_OCTET_STRING *requestHash;
    ASN1_ENUMERATED *responseCode;
    ASN1_OCTET_STRING *certificate;
    ASN1_INTEGER *cAContributionValue;
} ISE_INNERATRESPONSE;

DECLARE_ASN1_FUNCTIONS(ISE_INNERATRESPONSE);
DECLARE_ASN1_DUP_FUNCTION(ISE_INNERATRESPONSE);
DECLARE_ASN1_PRINT_FUNCTION(ISE_INNERATRESPONSE);
#define d2i_ISE_INNERATRESPONSE_bio(bp,p) ASN1_d2i_bio_of(ISE_INNERATRESPONSE,ISE_INNERATRESPONSE_new,d2i_ISE_INNERATRESPONSE,bp,p)
#define i2d_ISE_INNERATRESPONSE_bio(bp,o) ASN1_i2d_bio_of(ISE_INNERATRESPONSE,i2d_ISE_INNERATRESPONSE,bp,o)
#define d2i_ISE_INNERATRESPONSE_fp(fp,p) ASN1_d2i_fp_of(ISE_INNERATRESPONSE,ISE_INNERATRESPONSE_new,d2i_ISE_INNERATRESPONSE,fp,p)
#define i2d_ISE_INNERATRESPONSE_fp(fp,p) ASN1_i2d_fp_of(ISE_INNERATRESPONSE,i2d_ISE_INNERATRESPONSE,fp,p)

#define ISE_ATRC_ok                                 0
//  -- ITS->AA
#define ISE_ATRC_ITS_AA_CANTPARSE                   1 // valid for any structure
#define ISE_ATRC_ITS_AA_BADCONTENTTYPE              2 // not encrypted, not signed, not authorizationrequest
#define ISE_ATRC_ITS_AA_IMNOTTHERECIPIENT           3 // the "recipients" of the outermost encrypted data doesn't include me
#define ISE_ATRC_ITS_AA_UNKNOWNENCRYPTIONALGORITHM  4 // either kexalg or contentencryptionalgorithm
#define ISE_ATRC_ITS_AA_DECRYPTIONFAILED            5 // works for ECIES-HMAC and AES-CCM
#define ISE_ATRC_ITS_AA_KEYSDONTMATCH               6 // HMAC keyTag verification fails
#define ISE_ATRC_ITS_AA_INCOMPLETEREQUEST           7 // some elements are missing
#define ISE_ATRC_ITS_AA_INVALIDENCRYPTIONKEY        8 // the responseEncryptionKey is bad
#define ISE_ATRC_ITS_AA_OUTOFSYNCREQUEST            9 // signingTime is outside acceptable limits
#define ISE_ATRC_ITS_AA_UNKNOWNEA                  10 // the EA identified by eaId is unknown to me
#define ISE_ATRC_ITS_AA_INVALIDEA                  11 // the EA certificate is revoked
#define ISE_ATRC_ITS_AA_DENIEDPERMISSIONS          12 // I, the AA, deny the requested permissions
//  -- AA->EA
#define ISE_ATRC_AA_EA_CANTREACHEA                 13 // the EA is unreachable (network error?)
//  -- EA->AA
#define ISE_ATRC_EA_AA_CANTPARSE                   14 // valid for any structure
#define ISE_ATRC_EA_AA_BADCONTENTTYPE              15 // not encrypted, not signed, not authorizationrequest
#define ISE_ATRC_EA_AA_IMNOTTHERECIPIENT           16 // the "recipients" of the outermost encrypted data doesn't include me
#define ISE_ATRC_EA_AA_UNKNOWNENCRYPTIONALGORITHM  17 // either kexalg or contentencryptionalgorithm
#define ISE_ATRC_EA_AA_DECRYPTIONFAILED            18 // works for ECIES-HMAC and AES-CCM
//  -- TODO: continuer
#define ISE_ATRC_TODO_INVALIDAA                    19 // the AA certificate presented is invalid/revoked/whatever
#define ISE_ATRC_TODO_INVALIDAASIGNATURE           20 // the AA certificate presented can't validate the request signature
#define ISE_ATRC_TODO_WRONGEA                      21 // the encrypted signature doesn't designate me as the EA
#define ISE_ATRC_TODO_UNKNOWNITS                   22 // can't retrieve the EC/ITS in my DB
#define ISE_ATRC_TODO_INVALIDSIGNATURE             23 // signature verification of the request by the EC fails
#define ISE_ATRC_TODO_INVALIDENCRYPTIONKEY         24 // signature is good, but the key is bad
#define ISE_ATRC_TODO_DENIEDPERMISSIONS            25 // permissions not granted
#define ISE_ATRC_TODO_DENIEDTOOMANYCERTS           26 // parallel limit

