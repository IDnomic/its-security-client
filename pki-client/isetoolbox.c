#include "ise_asn1.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "ise_asn1.h"
#include "isetoolbox.h"

// TODO: more debug log

// check openssl version
#if OPENSSL_VERSION_NUMBER < 0x01000200fL
  #error "You need OpenSSL version 1.0.2 or better."
#endif

unsigned char *ISE_PUBLICKEY_HashedId8(EC_KEY *key)
{
    int ret = 0;
    ISE_PUBLICKEY *pubkey = NULL;
    int pplen = 0;
    unsigned char *ppbuf = NULL;
    unsigned char *fullhash = NULL;
    unsigned char *hashedid8 = NULL;

    ISE_PUBLICKEY_set(&pubkey, key);
    if (!pubkey)
        goto done;

    pplen = i2d_ISE_PUBLICKEY(pubkey, &ppbuf);
    if (pplen <= 0)
        goto done;
    fullhash = hashthis(ppbuf, pplen, EVP_sha256());
    hashedid8 = malloc(8);
    if (!hashedid8)
        goto done;
    memcpy(hashedid8, fullhash+24, 8);

    ret = 1;

done:
    if (pubkey) ISE_PUBLICKEY_free(pubkey);
    if (fullhash) free(fullhash);
    if (ppbuf) OPENSSL_free(ppbuf);
    if (ret == 0)
        if (hashedid8) { free(hashedid8); hashedid8 = NULL; }
    return hashedid8;
}


ASN1_OCTET_STRING *findsignedmessagedigest(STACK_OF(X509_ALGOR) *signedAttributes)
{
    X509_ALGOR *attr = NULL;
    ASN1_OCTET_STRING *dgst = NULL;
    int i;

    for(i = 0; i < sk_X509_ALGOR_num(signedAttributes); i++)
    {
        attr = sk_X509_ALGOR_value(signedAttributes, i);
        if ((OBJ_obj2nid(attr->algorithm) == NID_ISE_attrs_messageDigest) && (attr->parameter->type == V_ASN1_OCTET_STRING))
        {
            dgst = attr->parameter->value.octet_string;
            break;
        }
    }

    return dgst;
}


ASN1_OBJECT *findsignedcontenttype(STACK_OF(X509_ALGOR) *signedAttributes)
{
    X509_ALGOR *attr = NULL;
    ASN1_OBJECT *signedct = NULL;
    int i;

    for(i = 0; i < sk_X509_ALGOR_num(signedAttributes); i++)
    {
        attr = sk_X509_ALGOR_value(signedAttributes, i);
        if ((OBJ_obj2nid(attr->algorithm) == NID_ISE_attrs_contentType) && (attr->parameter->type == V_ASN1_OBJECT))
        {
            signedct = attr->parameter->value.object;
            break;
        }
    }

    return signedct;
}


int ASN1_OBJECT_cmp(ASN1_OBJECT *o1, ASN1_OBJECT *o2)
{
    int res = 0;
    int alen1 = 0,
        alen2 = 0,
        minlen = 0;

    if (!o1 && !o2)
    {
        res = 0;
        goto done;
    }

    if (!o1)
    {
        res = -1;
        goto done;
    }

    if (!o2)
    {
        res = 1;
        goto done;
    }

    alen1 = o1->length;
    alen2 = o2->length;

    if (alen1 < alen2)
        minlen = alen1;
    else
        minlen = alen2;

    res = memcmp(o1->data, o2->data, minlen);

    if (!res && (alen1 != alen2))
        res = alen1<alen2?-1:1;

done:
    /* Cleanup */
    return res;
}


ISE_INNERECREQUEST *buildInnerECRequest(char *canonicalId,
        unsigned char *wantedSubjectAttributes, int attributeslen,
        unsigned char *wantedValidityRestrictions, int restrictionslen,
        EC_KEY *responseDecryptionKey)
{
    int ret = 0;
    ISE_INNERECREQUEST *innerECreq = NULL;
    unsigned char requestIdentifier[16];


    /* Sanity checks */
    if (!canonicalId)
        goto done;
    if (!wantedSubjectAttributes)
        goto done;
    if (!responseDecryptionKey)
        goto done;

    innerECreq = ISE_INNERECREQUEST_new();
    if (!innerECreq)
    {
        //GENERR(-1, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /* First the random request identifier */
    RAND_pseudo_bytes(requestIdentifier, 16);
    if (ASN1_OCTET_STRING_set(innerECreq->requestIdentifier, requestIdentifier, 16) != 1)
    {
        //GENERR(-1, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /* Set the itsId */
    if (ASN1_STRING_set(innerECreq->itsId, canonicalId, -1) != 1)
    {
        //GENERR(-1, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /* The wantedSubjectAttributes */
    if (ASN1_OCTET_STRING_set(innerECreq->wantedSubjectAttributes, wantedSubjectAttributes, attributeslen) != 1)
    {
        //GENERR(-1, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /* Set the wanted validity restrictions */
    if (wantedValidityRestrictions)
    {
        innerECreq->wantedValidityRestrictions = ASN1_OCTET_STRING_new();
        if (!(innerECreq->wantedValidityRestrictions))
        {
            //GENERR(-1, ERR_R_MALLOC_FAILURE);
            goto done;
        }
        if (ASN1_OCTET_STRING_set(innerECreq->wantedValidityRestrictions, wantedValidityRestrictions, restrictionslen) != 1)
        {
            //GENERR(-1, ERR_R_MALLOC_FAILURE);
            goto done;
        }
    }

    /* And the responseEncryptionKey */
    ISE_PUBLICKEY_set(&(innerECreq->responseEncryptionKey), responseDecryptionKey);
    if (!(innerECreq->responseEncryptionKey))
        goto done;

    /* Everything's fine */
    ret = 1;

done:
    /* Cleanup */
    if (!ret)
    {
        if (innerECreq) ISE_INNERECREQUEST_free(innerECreq);
        innerECreq = NULL;
    }
    return innerECreq;
}


ISE_SIGNEDDATA *buildSignedData(ASN1_OBJECT *signedContentType, databuf *payload, int detached)
{
    int ret = 0;
    ISE_SIGNEDDATA *signedData = NULL;

    /* Sanity checks */
    if (!signedContentType)
        goto done;
    if (!detached && !payload)
        goto done;

    /* Allocate SignedData structure */
    signedData = ISE_SIGNEDDATA_new();
    if (!signedData)
        goto done;

    /* Set the signedContentType */
    ASN1_OBJECT_free(signedData->signedContentType);
    signedData->signedContentType = ASN1_OBJECT_dup(signedContentType);
    if (!(signedData->signedContentType))
        goto done;

    /* the payload */
    if (!detached)
    {
        signedData->signedContent = ASN1_OCTET_STRING_new();
        if (!(signedData->signedContentType))
            goto done;
        if (ASN1_OCTET_STRING_set(signedData->signedContent, payload->data, payload->datalen) != 1)
            goto done;
    }

    /* Everything's fine */
    ret = 1;

done:
    /* Cleanup */
    if (!ret)
    {
        if (signedData) ISE_SIGNEDDATA_free(signedData);
        signedData = NULL;
    }
    return signedData;
}


int signSignedData(ISE_SIGNEDDATA *signedData, databuf *payload, unsigned char *signerId, EC_KEY *key, int taiutc, int addhashalg)
{
    int ret = 0;
    X509_ALGOR *attr = NULL;
    ISE_SIGNERINFO *si = NULL;
    ASN1_OCTET_STRING *os = NULL;
    unsigned char *fullhash = NULL;
    ASN1_OCTET_STRING *digest_os = NULL;
    ASN1_INTEGER *signingtime_int = NULL;
    EVP_MD_CTX *mdctxsig = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *abuf = NULL;
    int alen;
    size_t siglen;


    /* Sanity checks */
    if (!signedData)
        goto done;
    if (!key)
        goto done;
    if (!(signedData->signedContent) && !payload)
        goto done;

    /* Add SHA256 in the hashAlgorithms */
    if (addhashalg)
    {
        attr = X509_ALGOR_new();
        if (!attr)
            goto done;
        X509_ALGOR_set0(attr, OBJ_nid2obj(NID_sha256), V_ASN1_UNDEF, NULL);
        if (!sk_X509_ALGOR_push(signedData->hashAlgorithms, attr))
            goto done;
        attr = NULL;
    }

    /* Allocate and fill a SignerInfo */
    si = ISE_SIGNERINFO_new();
    if (!si)
        goto done;
    /* Set the signer if given a signerid */
    if (signerId)
    {
        si->signer = ISE_SIGNERIDENTIFIER_new();
        if (!(si->signer))
            goto done;
        si->signer->type = 1;
        si->signer->value.certificateDigest = ISE_CERTIFICATEDIGEST_new();
        if (!(si->signer->value.certificateDigest))
            goto done;
        os = ASN1_OCTET_STRING_new();
        if (!os)
            goto done;
        if (ASN1_OCTET_STRING_set(os, signerId, 8) != 1)
            goto done;
        si->signer->value.certificateDigest->digest = os;
        os = NULL;
    }

    /* digestAlgorithm: keep the DEFAULT */

    /* signatureAlgorithm: keep the DEFAULT */

    /* First attribute: messageDigest */
    /* Hash payload data */
    if (signedData->signedContent)
        fullhash = hashthis(signedData->signedContent->data, signedData->signedContent->length, EVP_sha256());
    else
        fullhash = hashthis(payload->data, payload->datalen, EVP_sha256());

    digest_os = ASN1_OCTET_STRING_new();
    if (!digest_os)
        goto done;
    if (ASN1_OCTET_STRING_set(digest_os, fullhash, 32) != 1)
        goto done;

    attr = X509_ALGOR_new();
    if (!attr)
        goto done;
    X509_ALGOR_set0(attr, OBJ_nid2obj(NID_ISE_attrs_messageDigest), V_ASN1_OCTET_STRING, ASN1_OCTET_STRING_dup(digest_os));
    if (!sk_X509_ALGOR_push(si->signedAttributes, attr))
        goto done;
    attr = NULL;

    /* Next attribute: contentType */
    attr = X509_ALGOR_new();
    if (!attr)
        goto done;
    X509_ALGOR_set0(attr, OBJ_nid2obj(NID_ISE_attrs_contentType), V_ASN1_OBJECT, ASN1_OBJECT_dup(signedData->signedContentType));
    if (!sk_X509_ALGOR_push(si->signedAttributes, attr))
        goto done;
    attr = NULL;

    /* Next attribute: signingTime */
    signingtime_int = ASN1_INTEGER_new();
    if (!signingtime_int)
        goto done;
    if (!ASN1_INTEGER_set(signingtime_int, time(NULL)+taiutc-1072915200))
        goto done;
    attr = X509_ALGOR_new();
    if (!attr)
        goto done;
    X509_ALGOR_set0(attr, OBJ_nid2obj(NID_ISE_attrs_signingTime), V_ASN1_INTEGER, signingtime_int);
    signingtime_int = NULL;
    if (!sk_X509_ALGOR_push(si->signedAttributes, attr))
        goto done;
    attr = NULL;

    /* Enclose key into an EVP_PKEY */
    pkey = EVP_PKEY_new();
    if (!pkey)
        goto done;
    if (EVP_PKEY_set1_EC_KEY(pkey, key) != 1)
        goto done;

    /* Do the signature */
    if ((mdctxsig = EVP_MD_CTX_create()) == NULL)
        goto done;
    if (EVP_DigestSignInit(mdctxsig, &pctx, EVP_sha256(), NULL, pkey) <= 0)
        goto done;
    pkey = NULL;
    if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_SIGN, EVP_PKEY_CTRL_CMS_SIGN, 0, si) <= 0)
        goto done;
    alen = ASN1_item_i2d((ASN1_VALUE *)si->signedAttributes, &abuf, ASN1_ITEM_rptr(ISE_SIGNEDDATA_ATTRIBUTES_SIGN));
    if (!abuf)
        goto done;
    if (EVP_DigestSignUpdate(mdctxsig, abuf, alen) <= 0)
        goto done;
    if (EVP_DigestSignFinal(mdctxsig, NULL, &siglen) <= 0)
        goto done;
    OPENSSL_free(abuf);
    abuf = OPENSSL_malloc(siglen);
    if (!abuf)
        goto done;
    if (EVP_DigestSignFinal(mdctxsig, abuf, &siglen) <= 0)
        goto done;
    if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_SIGN, EVP_PKEY_CTRL_CMS_SIGN, 1, si) <= 0)
        goto done;
    ASN1_STRING_set0(si->signature, abuf, siglen);
    abuf = NULL;

    /* Add the current signerInfo to the stack */
    sk_ISE_SIGNERINFO_push(signedData->signerInfos, si);
    si = NULL;

    /* Everything's fine */
    ret = 1;

done:
    /* Cleanup */
    if (attr) X509_ALGOR_free(attr);
    if (si) ISE_SIGNERINFO_free(si);
    if (os) ASN1_OCTET_STRING_free(os);
    if (fullhash) free(fullhash);
    if (digest_os) ASN1_OCTET_STRING_free(digest_os);
    if (signingtime_int) ASN1_INTEGER_free(signingtime_int);
    if (mdctxsig) EVP_MD_CTX_destroy(mdctxsig);
    //EVP_PKEY_CTX *pctx ?;
    if (pkey) EVP_PKEY_free(pkey);
    if (abuf) OPENSSL_free(abuf);
    return ret;  
}


int verifySignerInfoSignature(ISE_SIGNERINFO *si, EC_KEY *key)
{
    int ret = 0;
    int alen = 0;
    unsigned char *abuf = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *mdctxsig = NULL;
    const EVP_MD *md = NULL;

    /* Enclose key into an EVP_PKEY */
    pkey = EVP_PKEY_new();
    if (!pkey)
        goto done;
    if (EVP_PKEY_set1_EC_KEY(pkey, key) != 1)
        goto done;

    /* Do the verification */
    if (si->signatureAlgorithm)
        md = EVP_get_digestbyobj(si->signatureAlgorithm->algorithm);
    else
        md = EVP_sha256();
    if ((mdctxsig = EVP_MD_CTX_create()) == NULL)
        goto done;
    if (EVP_DigestVerifyInit(mdctxsig, &pctx, md, NULL, pkey) <= 0)
        goto done;
    pkey = NULL;
    alen = ASN1_item_i2d((ASN1_VALUE *)si->signedAttributes, &abuf, ASN1_ITEM_rptr(ISE_SIGNEDDATA_ATTRIBUTES_SIGN));
    if (EVP_DigestVerifyUpdate(mdctxsig, abuf, alen) <= 0)
        goto done;
    if (EVP_DigestVerifyFinal(mdctxsig, si->signature->data, si->signature->length) <= 0)
        goto done;

    /* Everything's fine */
    ret = 1;

done:
    if (abuf) OPENSSL_free(abuf);
    if (pkey) EVP_PKEY_free(pkey);
    return ret;
}


int verifySignedData(ISE_SIGNEDDATA *signedData, unsigned char *signerid, EC_KEY *key)
{
    int ret = 0;
    ISE_SIGNERINFO *si = NULL;
    STACK_OF(ISE_SIGNERINFO) *stsi = signedData->signerInfos;
    int i;
    int signatureisok = 0;
    X509_ALGOR *algor = NULL;
    ASN1_OCTET_STRING *signerdigest = NULL;
    ASN1_OCTET_STRING *signedmessagedigest = NULL;
    ASN1_OBJECT *signedcontenttype = NULL;
    unsigned char *fullhash = NULL;

    /* Hash the content */
    fullhash = hashthis(signedData->signedContent->data, signedData->signedContent->length, EVP_sha256());

    /* Loop through SignerInfos */
    for(i = 0; i < sk_ISE_SIGNERINFO_num(stsi); i++)
    {
        /* I want a signer declared as a certificateDigest with default alg or SHA256, whose digest is equal to signerid */
        si = sk_ISE_SIGNERINFO_value(stsi, i);
        if (!(si->signer))
            continue;
        if (si->signer->type != 1)
            continue;
        algor = si->signer->value.certificateDigest->algorithm;
        if (algor && (OBJ_obj2nid(algor->algorithm) != NID_sha256))
            continue;
        signerdigest = si->signer->value.certificateDigest->digest;
        if ((!signerdigest) || (signerdigest->length != 8) || memcmp(signerid, signerdigest->data, 8))
            continue;

        /* Found a potential candidate, verify the signature */
        if (!verifySignerInfoSignature(si, key))
            continue;

        /* Signature is good, compare the digests */
        signedmessagedigest = findsignedmessagedigest(si->signedAttributes);
        if (!signedmessagedigest)
            continue;
        if (signedmessagedigest->length != 32)
            continue;
        if (memcmp(signedmessagedigest->data, fullhash, 32))
            continue;

        /* Compare the signedContentType */
        signedcontenttype = findsignedcontenttype(si->signedAttributes);
        if (!signedcontenttype)
            continue;
        if (ASN1_OBJECT_cmp(signedcontenttype, signedData->signedContentType))
            continue;

        signatureisok = 1;
        break;
    }

    /* If we haven't found a good signature, abort */
    if (!signatureisok)
        goto done;

    /* Everything's fine */
    ret = 1;

done:
    if (fullhash) free(fullhash);
    return ret;
}



/* Caller MUST ensure that *recipientId is 8 octets long, and *aeskey is 16 octets long, or die */
ISE_RECIPIENTINFO *encryptECIES(unsigned char *recipientId, unsigned char *aeskey, EC_KEY *recipientKey)
{
    int ret = 0;
    ISE_RECIPIENTINFO *ri = NULL;
    ISE_ECIESENCRYPTEDKEY103097 *ekm = NULL;
    EC_GROUP *group = NULL;
    EC_KEY *tmpsenderkey = NULL;
    unsigned char K[KEYLEN+32],
                  K1[KEYLEN],
                  K2[32],
                  C[KEYLEN];
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    int i;

    /* Sanity checks */
    if (!recipientId)
        goto done;
    if (!aeskey)
        goto done;
    if (!recipientKey)
        goto done;

    /* Allocate a new RECIPIENTINFO */
    ri = ISE_RECIPIENTINFO_new();
    if (!ri)
        goto done;

    /* recipient */
    if (ASN1_OCTET_STRING_set(ri->recipient, recipientId, 8) != 1)
        goto done;

    /* kexalgid is left as the DEFAULT */


    /* Build the EncryptedKeyMaterial */
    ekm = ISE_ECIESENCRYPTEDKEY103097_new();
    if (!ekm)
        goto done;

    /* (optional) Validate that w is a valid point on the curve (7.2.2) */
    if (EC_KEY_check_key(recipientKey) == 0)
        goto done;

    /* Generate temporary keypair (u,v) */
    tmpsenderkey = EC_KEY_new();
    if (!tmpsenderkey)
        goto done;

    /* TODO: should take the group from recipientkey */
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group)
        goto done;

    EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED);

    if (EC_KEY_set_group(tmpsenderkey, group) == 0)
        goto done;

    if (!EC_KEY_generate_key(tmpsenderkey))
        goto done;

    /* Compute a secret value z from u and w using ECSVDP-DHC (9.2.1) */
    /* Convert the secret value z into Z using FE2OSP */
    /* Convert v into V using FE2OSP routines */
    /* Let VZ=Z */
    /* Derive secret key K from VZ using KDF2-SHA256, length of K is 128+256 bits */
    EC_KEY_set_flags(tmpsenderkey, EC_FLAG_COFACTOR_ECDH);
    ECDH_compute_key(K, sizeof(K), EC_KEY_get0_public_key(recipientKey), tmpsenderkey, &ETSI_ECIES_KDF);

    /* K1 is the left-most 128 bits of K */
    /* K2 is the remaining 256 bits of K */
    memcpy(K1, K, 16);
    memcpy(K2, K+16, 32);

    /* C = M XOR K1 */
    for(i = 0; i < 16; i++)
        C[i] = aeskey[i] ^ K1[i];
    if (ASN1_OCTET_STRING_set(ekm->c, C, sizeof(C)) != 1)
        goto done;

    /* Compute the tag T=MAC1_K2(C), we'll retain the leftmost 16 octets */
    if (HMAC(EVP_sha256(), K2, sizeof(K2), C, sizeof(C), hmac_result, &hmac_len) == NULL)
        goto done;
    if (ASN1_OCTET_STRING_set(ekm->t, hmac_result, 16) != 1)
        goto done;

    /* Store the sender public key */
    ISE_PUBLICKEY_set(&(ekm->v), tmpsenderkey);
    if (!(ekm->v))
        goto done;

    /* Encode the ISE_ECIESENCRYPTEDKEY103097 into an OCTET STRING */
    ri->encryptedKeyMaterial->length = i2d_ISE_ECIESENCRYPTEDKEY103097(ekm, &ri->encryptedKeyMaterial->data);
    if (ri->encryptedKeyMaterial->length <= 0)
        goto done;

    /* Everything's fine here */
    ret = 1;

done:
    if (tmpsenderkey) EC_KEY_free(tmpsenderkey);
    if (group) EC_GROUP_free(group);
    if (ekm) ISE_ECIESENCRYPTEDKEY103097_free(ekm);
    if (ret == 0)
        if (ri)
        {
            ISE_RECIPIENTINFO_free(ri);
            ri = NULL;
        }
    return ri;
}


/* Caller MUST ensure that *recipientId is 8 octets long, *aeskey is 16 octets long, and recipientInfos is correct, or die */
int decryptECIES(unsigned char *myHashedId8, unsigned char *aeskey, EC_KEY *key, STACK_OF(ISE_RECIPIENTINFO) *recipientInfos)
{
    int ret = 0;
    int foundit = 0;
    ISE_RECIPIENTINFO *ri = NULL;
    ISE_ECIESENCRYPTEDKEY103097 *ekm = NULL;
    BIO *biomem = NULL;
    EC_KEY *tmpsenderkey = NULL;
    unsigned char K[KEYLEN+32],
                  K1[KEYLEN],
                  K2[32];
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    int i;
    int riloop;

    EC_KEY_set_flags(key, EC_FLAG_COFACTOR_ECDH);

    /* We'll try all the recipientInfo until we get a success */
    for(riloop = 0; riloop < sk_ISE_RECIPIENTINFO_num(recipientInfos); riloop++)
    {
        ri = sk_ISE_RECIPIENTINFO_value(recipientInfos, riloop);

        /* Check if it's a possible candidate */
        if (ri->recipient->length != 8)
            goto cleanandcheck;
        if (memcmp(ri->recipient->data, myHashedId8, 8))
            goto cleanandcheck;
        if ((ri->kexalgid) && (OBJ_obj2nid(ri->kexalgid->algorithm) != NID_ISE_algos_ecies_103097))
            goto cleanandcheck;

        /* Looks good, read the encryptedKeyMaterial */
        biomem = BIO_new(BIO_s_mem());
        BIO_write(biomem, ri->encryptedKeyMaterial->data, ri->encryptedKeyMaterial->length);
        ekm = d2i_ISE_ECIESENCRYPTEDKEY103097_bio(biomem, &ekm);
        BIO_free(biomem);
        biomem = NULL;
        if (!ekm)
            goto cleanandcheck;

        /* ekm is syntaxically correct, perform additional checks */
        if (!(ekm->c) || (ekm->c->length != KEYLEN))
            goto cleanandcheck;
        if (!(ekm->t) || (ekm->t->length != KEYLEN))
            goto cleanandcheck;
        ISE_PUBLICKEY_to_EC_KEY(&tmpsenderkey, ekm->v);
        if (!tmpsenderkey)
            goto cleanandcheck;

        /* (optional) Validate that w is a valid point on the curve (7.2.2) */
        if (EC_KEY_check_key(tmpsenderkey) == 0)
            goto cleanandcheck;

        /* Compute a secret value z from u and w using ECSVDP-DHC (9.2.1) */
        /* Convert the secret value z into Z using FE2OSP */
        /* Convert v into V using FE2OSP routines */
        /* Let VZ=Z */
        /* Derive secret key K from VZ using KDF2-SHA256, length of K is 128+256 bits */
        ECDH_compute_key(K, sizeof(K), EC_KEY_get0_public_key(tmpsenderkey), key, &ETSI_ECIES_KDF);

        /* K1 is the left-most 128 bits of K */
        /* K2 is the remaining 256 bits of K */
        memcpy(K1, K, 16);
        memcpy(K2, K+16, 32);

        /* Compute the tag T=MAC1_K2(C), and compare the leftmost 16 octets */
        if (HMAC(EVP_sha256(), K2, sizeof(K2), ekm->c->data, ekm->c->length, hmac_result, &hmac_len) == NULL)
            goto cleanandcheck;
        if (hmac_len != 32)
            goto cleanandcheck;
        if (memcmp(hmac_result, ekm->t->data, 16))
            goto cleanandcheck;

        /* We found it! */
        foundit = 1;

        /* M = C XOR K1 */
        for(i = 0; i < KEYLEN; i++)
            aeskey[i] = ekm->c->data[i] ^ K1[i];

cleanandcheck:
        if (tmpsenderkey) EC_KEY_free(tmpsenderkey);
        if (ekm) ISE_ECIESENCRYPTEDKEY103097_free(ekm);
        if (foundit)
            break;
        else
            continue;
    }

    if (!foundit)
        goto done;

    /* Everything's fine here */
    ret = 1;

done:
    return ret;
}


int genSecretAESCCMParameters(unsigned char **aeskey, unsigned char **aesccmnonce)
{
    int ret = 0;
    unsigned char *tmpaeskey = NULL;
    unsigned char *tmpaesccmnonce = NULL;

    /* Sanity checks */
    if (!aeskey)
        goto done;
    if (!aesccmnonce)
        goto done;

    /* Generate a key */
    tmpaeskey = malloc(KEYLEN);
    if (!tmpaeskey)
        goto done;
    RAND_pseudo_bytes(tmpaeskey, KEYLEN);

    /* And a nonce */
    tmpaesccmnonce = malloc(NONCELEN);
    if (!tmpaesccmnonce)
        goto done;
    RAND_pseudo_bytes(tmpaesccmnonce, NONCELEN);

    /* Everything's fine */
    ret = 1;

done:
    if (ret == 1)
    {
        *aeskey = tmpaeskey;
        *aesccmnonce = tmpaesccmnonce;
    }
    return ret;
}


ISE_ENCRYPTEDDATA *buildEncryptedData(ASN1_OBJECT *encryptedContentType, databuf *payload, unsigned char *aesccmnonce)
{
    int ret = 0;
    ISE_ENCRYPTEDDATA *encryptedData = NULL;
    ISE_CCMDEFAULTPARAMETERS *ccmparams = NULL;
    ASN1_STRING *ccmparamstr = NULL;
    X509_ALGOR *algor = NULL;

    /* Sanity checks */
    if (!encryptedContentType)
        goto done;
    if (!aesccmnonce)
        goto done;

    /* Allocate EncryptedData structure */
    encryptedData = ISE_ENCRYPTEDDATA_new();
    if (!encryptedData)
        goto done;

    /* Copy the encryptedContentType */
    ASN1_OBJECT_free(encryptedData->encryptedContentType);
    encryptedData->encryptedContentType = ASN1_OBJECT_dup(encryptedContentType);
    if (!(encryptedData->encryptedContentType))
        goto done;

    /* Set the encryptedContent */
    if (payload)
    {
        encryptedData->encryptedContent = ASN1_OCTET_STRING_new();
        if (!(encryptedData->encryptedContent))
            goto done;
        if (ASN1_OCTET_STRING_set(encryptedData->encryptedContent, payload->data, payload->datalen) != 1)
            goto done;
    }

    /* Set the encryptionAlgorithm */
    ccmparams = ISE_CCMDEFAULTPARAMETERS_new();
    if (!ccmparams)
        goto done;
    if (ASN1_OCTET_STRING_set(ccmparams->aesNonce, aesccmnonce, NONCELEN) != 1)
        goto done;
    ccmparamstr = ASN1_STRING_new();
    if (!ccmparamstr)
        goto done;
    ccmparamstr->length = i2d_ISE_CCMDEFAULTPARAMETERS(ccmparams, &ccmparamstr->data);
    if (ccmparamstr->length <= 0)
        goto done;
    algor = X509_ALGOR_new();
    if (!algor)
        goto done;
    X509_ALGOR_set0(algor, OBJ_nid2obj(NID_ISE_algos_aes128CCM_103097), V_ASN1_SEQUENCE, ccmparamstr);
    ccmparamstr = NULL;
    X509_ALGOR_free(encryptedData->encryptionAlgorithm);
    encryptedData->encryptionAlgorithm = algor;
    algor = NULL;

    /* Everything's fine */
    ret = 1;

done:
    if (!ret)
    {
        if (encryptedData) ISE_ENCRYPTEDDATA_free(encryptedData);
        encryptedData = NULL;
    }
    if (ccmparams) ISE_CCMDEFAULTPARAMETERS_free(ccmparams);
    if (ccmparamstr) ASN1_STRING_free(ccmparamstr);
    if (algor) X509_ALGOR_free(algor);
    return encryptedData;
}


int addEncryptedDataRecipient(ISE_ENCRYPTEDDATA *encryptedData, unsigned char *recipientId, unsigned char *aeskey, EC_KEY *key)
{
    int ret = 0;
    ISE_RECIPIENTINFO *ri = NULL;

    /* Sanity checks */
    if (!encryptedData)
        goto done;
    if (!recipientId)
        goto done;
    if (!aeskey)
        goto done;
    if (!key)
        goto done;

    /* Encrypt the key for this recipient */
    ri = encryptECIES(recipientId, aeskey, key);
    if (!ri)
        goto done;

    /* Add this recipient to the stack */
    if (!sk_ISE_RECIPIENTINFO_push(encryptedData->recipientInfos, ri))
        goto done;
    ri = NULL;

    /* Everything's fine */
    ret = 1;

done:
    if (ri) ISE_RECIPIENTINFO_free(ri);
    return ret;
}


int decrypt_ISE_ENCRYPTEDDATA(ISE_ENCRYPTEDDATA *encryptedData, unsigned char *myid, EC_KEY *mykey, databuf **output)
{
    int ret = 0;
    ISE_CCMDEFAULTPARAMETERS *ccmparameters = NULL;
    unsigned char *aeskey = NULL;
    databuf *inputbuf = NULL,
            *outputbuf = NULL;
    BIO *biomem = NULL;

    /* Perform some checks on it */
    if ((encryptedData->version) && (ASN1_INTEGER_get(encryptedData->version) != 0))
        goto done;

    /* Try to retrieve the AES key */
    aeskey = malloc(KEYLEN);
    if (!aeskey)
        goto done;
    if (!decryptECIES(myid, aeskey, mykey, encryptedData->recipientInfos))
        goto done;

    /* Check the encryptionAlgorithm */
    if (!(encryptedData->encryptionAlgorithm) || (OBJ_obj2nid(encryptedData->encryptionAlgorithm->algorithm) != NID_ISE_algos_aes128CCM_103097))
        goto done;

    /* Check and get the parameters */
    if (!(encryptedData->encryptionAlgorithm->parameter) || (encryptedData->encryptionAlgorithm->parameter->type != V_ASN1_SEQUENCE))
        goto done;
    biomem = BIO_new(BIO_s_mem());
    BIO_write(biomem, encryptedData->encryptionAlgorithm->parameter->value.sequence->data, encryptedData->encryptionAlgorithm->parameter->value.sequence->length);
    ccmparameters = d2i_ISE_CCMDEFAULTPARAMETERS_bio(biomem, &ccmparameters);
    BIO_free(biomem);
    biomem = NULL;
    if (!ccmparameters)
        goto done;
    if (!(ccmparameters->aesNonce) || (ccmparameters->aesNonce->length != NONCELEN))
        goto done;

    /* For this version, I don't allow for absent encryptedContent */
    if (!(encryptedData->encryptedContent))
        goto done;

    /* Do decrypt the payload */
    inputbuf = calloc(sizeof(*inputbuf), 1);
    if (!inputbuf)
        goto done;
    if (!pushbuf(inputbuf, encryptedData->encryptedContent->data, encryptedData->encryptedContent->length))
        goto done;
    if (!decryptccm(inputbuf, aeskey, ccmparameters->aesNonce->data, &outputbuf))
        goto done;

    /* Everything's fine */
    ret = 1;

done:
    /* Cleanup */
    if (ccmparameters) ISE_CCMDEFAULTPARAMETERS_free(ccmparameters);
    if (aeskey) free(aeskey);
    if (inputbuf) { if (inputbuf->data) free(inputbuf->data); free(inputbuf); }
    if (biomem) BIO_free(biomem);
    if (ret == 0)
    {
        if (outputbuf && outputbuf->data) free(outputbuf->data);
        if (outputbuf) free(outputbuf);
    }
    else
        *output = outputbuf;
    return ret;
}




ISE_DATA *buildData(ASN1_OBJECT *contentType, databuf *payload)
{
    int ret = 0;
    ISE_DATA *data = NULL;

    /* Sanity checks */
    if (!contentType)
        goto done;

    /* Allocate Data structure */
    data = ISE_DATA_new();
    if (!data)
        goto done;

    /* Copy the contentType */
    ASN1_OBJECT_free(data->contentType);
    data->contentType = ASN1_OBJECT_dup(contentType);
    if (!(data->contentType))
        goto done;

    /* Set the content */
    if (payload)
    {
        data->content = ASN1_OCTET_STRING_new();
        if (!(data->content))
            goto done;
        if (ASN1_OCTET_STRING_set(data->content, payload->data, payload->datalen) != 1)
            goto done;
    }

    /* Everything's fine */
    ret = 1;

done:
    if (!ret)
    {
        if (data) ISE_DATA_free(data);
        data = NULL;
    }
    return data;
}


ISE_SHAREDATREQUEST *buildSharedATRequest(unsigned char *eaId, unsigned char *keyTag,
        unsigned char *wantedSubjectAttributes, int attributeslen,
        unsigned char *wantedValidityRestrictions, int restrictionslen,
        long wantedStart, EC_KEY *responseDecryptionKey)
{
    int ret = 0;
    ISE_SHAREDATREQUEST *sharedATreq = NULL;
    unsigned char requestIdentifier[16];

    /* Sanity checks */
    if (!eaId)
        goto done;
    if (!keyTag)
        goto done;
    if (!wantedSubjectAttributes)
        goto done;
    if (!responseDecryptionKey)
        goto done;

    sharedATreq = ISE_SHAREDATREQUEST_new();
    if (!sharedATreq)
    {
        //GENERR(-1, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /* First the random request identifier */
    RAND_pseudo_bytes(requestIdentifier, 16);
    if (ASN1_OCTET_STRING_set(sharedATreq->requestIdentifier, requestIdentifier, 16) != 1)
    {
        //GENERR(-1, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /* Set the eaId */
    if (ASN1_OCTET_STRING_set(sharedATreq->eaId, eaId, 8) != 1)
    {
        //GENERR(-1, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /* Set the keyTag */
    if (ASN1_OCTET_STRING_set(sharedATreq->keyTag, keyTag, 16) != 1)
    {
        //GENERR(-1, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /* Set the wantedSubjectAttributes */
    if (ASN1_OCTET_STRING_set(sharedATreq->wantedSubjectAttributes, wantedSubjectAttributes, attributeslen) != 1)
    {
        //GENERR(-1, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /* Set the wantedValidityRestrictions */
    if (wantedValidityRestrictions)
    {
        if (!(sharedATreq->wantedValidityRestrictions = ASN1_OCTET_STRING_new()))
        {
            //GENERR(-1, ERR_R_MALLOC_FAILURE);
            goto done;
        }
        if (ASN1_OCTET_STRING_set(sharedATreq->wantedValidityRestrictions, wantedValidityRestrictions, restrictionslen) != 1)
        {
            //GENERR(-1, ERR_R_MALLOC_FAILURE);
            goto done;
        }
    }

    /* Set the wantedStart */
    if (!ASN1_INTEGER_set(sharedATreq->wantedStart, wantedStart))
        goto done;

    /* And the responseEncryptionKey */
    ISE_PUBLICKEY_set(&(sharedATreq->responseEncryptionKey), responseDecryptionKey);
    if (!(sharedATreq->responseEncryptionKey))
        goto done;

    /* Everything's fine */
    ret = 1;

done:
    if (!ret)
    {
        if (sharedATreq) ISE_SHAREDATREQUEST_free(sharedATreq);
        sharedATreq = NULL;
    }
    return sharedATreq;
}


ISE_INNERATREQUEST *buildInnerATRequest(ISE_PUBLICKEY *verificationkey, ISE_PUBLICKEY *encryptionkey,
        unsigned char *hmackey, ISE_SHAREDATREQUEST *sharedATreq,
        ISE_ENCRYPTEDDATA *detachedEncryptedSignature)
{
    int ret = 0;
    ISE_INNERATREQUEST *innerATreq = NULL;

    /* Sanity checks */
    if (!verificationkey)
        goto done;
    if (!hmackey)
        goto done;
    if (!sharedATreq)
        goto done;
    if (!detachedEncryptedSignature)
        goto done;

    innerATreq = ISE_INNERATREQUEST_new();
    if (!innerATreq)
    {
        //GENERR(-1, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    ISE_PUBLICKEY_free(innerATreq->verificationKey);
    innerATreq->verificationKey = ISE_PUBLICKEY_dup(verificationkey);
    if (!innerATreq->verificationKey)
    {
        //GENERR(-1, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (encryptionkey)
    {
        innerATreq->encryptionKey = ISE_PUBLICKEY_dup(encryptionkey);
        if (!innerATreq->encryptionKey)
        {
            //GENERR(-1, ERR_R_MALLOC_FAILURE);
            goto done;
        }
    }
    if (ASN1_OCTET_STRING_set(innerATreq->hmacKey, hmackey, 32) != 1)
    {
        //GENERR(-1, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    ISE_SHAREDATREQUEST_free(innerATreq->signedByEC);
    innerATreq->signedByEC = ISE_SHAREDATREQUEST_dup(sharedATreq);
    if (!innerATreq->signedByEC)
    {
        //GENERR(-1, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    ISE_ENCRYPTEDDATA_free(innerATreq->detachedEncryptedSignature);
    innerATreq->detachedEncryptedSignature = ISE_ENCRYPTEDDATA_dup(detachedEncryptedSignature);
    if (!innerATreq->detachedEncryptedSignature)
    {
        //GENERR(-1, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /* Everything's fine */
    ret = 1;

done:
    if (!ret)
    {
        if (innerATreq) ISE_INNERATREQUEST_free(innerATreq);
        innerATreq = NULL;
    }
    return innerATreq;  
}
