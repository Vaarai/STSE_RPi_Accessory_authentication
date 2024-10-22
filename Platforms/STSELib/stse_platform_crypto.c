#include <stddef.h>

#include "stselib.h"
#include "mbedtls\ecdsa.h"

#include "mbedtls/sha1.h"
#include "mbedtls/sha3.h"
#include "mbedtls/sha256.h" /* SHA-256 only */
#include "mbedtls/sha512.h" /* SHA-384 & SHA-512 */

mbedtls_ecp_group_id stse_ecc_key_type_get_group_id(stse_ecc_key_type_t kt)
{
	switch(kt)
	{
		case STSE_ECC_KT_NIST_P_256:
			return MBEDTLS_ECP_DP_SECP256R1;
		case STSE_ECC_KT_NIST_P_384:
			return MBEDTLS_ECP_DP_SECP384R1;
		case STSE_ECC_KT_NIST_P_521:
			return MBEDTLS_ECP_DP_SECP521R1;
		case STSE_ECC_KT_BP_P_256:
			return MBEDTLS_ECP_DP_BP256R1;
		case STSE_ECC_KT_BP_P_384:
			return MBEDTLS_ECP_DP_BP384R1;
		case STSE_ECC_KT_BP_P_512:
			return MBEDTLS_ECP_DP_BP512R1;
		case STSE_ECC_KT_CURVE25519:
			return MBEDTLS_ECP_DP_CURVE25519;
		case STSE_ECC_KT_ED25519:
		case STSE_ECC_KT_INVALID:
		default:
			return MBEDTLS_ECP_DP_NONE;
	}
}

stse_ReturnCode_t stse_crypto_platform_init (void)
{
	/* TODO */
	return STSE_OK;
}

PLAT_UI32 stse_platform_Random (void)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_hash_compute(stse_hash_algorithm_t hash_algo,
									  PLAT_UI8 *pPayload, PLAT_UI32 payload_length,
									  PLAT_UI8 *pHash, PLAT_UI32 *hash_length)
{
	int mbedtls_ret = 1;

	switch (hash_algo)
	{
		case STSE_SHA_1:
			mbedtls_ret = mbedtls_sha1(pPayload, payload_length, pHash); break;
		case STSE_SHA_224:
			mbedtls_ret = mbedtls_sha256(pPayload, payload_length, pHash,1); break;
		case STSE_SHA_256:
			mbedtls_ret = mbedtls_sha256(pPayload, payload_length, pHash,0); break;
		case STSE_SHA_384:
			mbedtls_ret = mbedtls_sha512(pPayload, payload_length, pHash,1); break;
		case STSE_SHA_512:
			mbedtls_ret = mbedtls_sha512(pPayload, payload_length, pHash,0); break;
		case STSE_SHA3_256:
			mbedtls_ret = mbedtls_sha3(MBEDTLS_SHA3_256, pPayload, payload_length, pHash, *hash_length); break;
		case STSE_SHA3_384:
			mbedtls_ret = mbedtls_sha3(MBEDTLS_SHA3_384, pPayload, payload_length, pHash, *hash_length); break;
		case STSE_SHA3_512:
			mbedtls_ret = mbedtls_sha3(MBEDTLS_SHA3_512, pPayload, payload_length, pHash, *hash_length); break;
		case STSE_SHA_INVALID:
			return STSE_PLATFORM_INVALID_PARAMETER;
	}

	if (mbedtls_ret != 0)
	{
		return STSE_PLATFORM_HASH_ERROR;
	}
	return STSE_OK;
}

stse_ReturnCode_t stse_platform_ecc_generate_key_pair(
		stse_ecc_key_type_t key_type,
		PLAT_UI8 *pPrivKey,
		PLAT_UI8 *pPubKey)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_ecc_verify(
		stse_ecc_key_type_t key_type,
		const PLAT_UI8 *pPubKey,
		PLAT_UI8 *pDigest,
		PLAT_UI16 digestLen,
		PLAT_UI8 *pSignature)
{
	#define CHECH_MBED_RETURN	if (mbedtls_ret != 0) \
								{mbedtls_ecp_point_free(&public_ecp_point); \
								 mbedtls_ecp_group_free(&public_ecp_group); \
								 mbedtls_ecdsa_free(&ctx_verify); \
								 return STSE_PLATFORM_ECC_VERIFY_ERROR;}
	int mbedtls_ret = 1;

    mbedtls_ecp_point public_ecp_point;
	mbedtls_ecp_group public_ecp_group;
    mbedtls_ecdsa_context ctx_verify;

    mbedtls_ecp_point_init(&public_ecp_point);
	mbedtls_ecp_group_init(&public_ecp_group);
    mbedtls_ecdsa_init(&ctx_verify);
	
	mbedtls_ret = mbedtls_ecp_group_load(
		&public_ecp_group,
		stse_ecc_key_type_get_group_id(key_type));
	CHECH_MBED_RETURN;

	mbedtls_ret = mbedtls_ecp_point_read_binary(
		&public_ecp_group,
		&public_ecp_point,
		pPubKey,
		stse_ecc_info_table[key_type].signature_size);
	CHECH_MBED_RETURN;

	mbedtls_ret = mbedtls_ecp_set_public_key(
		stse_ecc_key_type_get_group_id(key_type), 
		&ctx_verify, 
		&public_ecp_point);
	CHECH_MBED_RETURN;

	mbedtls_ret = mbedtls_ecdsa_read_signature(
		&ctx_verify,
		pDigest, 
		digestLen,
		pSignature, 
		stse_ecc_info_table[key_type].signature_size);

	mbedtls_ecp_point_free(&public_ecp_point);
	mbedtls_ecp_group_free(&public_ecp_group);
    mbedtls_ecdsa_free(&ctx_verify);
	if (mbedtls_ret != 0)
	{
		return STSE_PLATFORM_ECC_VERIFY_ERROR;
	}
	return STSE_OK;
	#undef CHECH_MBED_RETURN
}

stse_ReturnCode_t stse_platform_ecc_sign(
		stse_ecc_key_type_t key_type,
		PLAT_UI8 *pPrivKey,
		PLAT_UI8 *pDigest,
		PLAT_UI16 digestLen,
		PLAT_UI8 *pSignature)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}


stse_ReturnCode_t stse_platform_ecc_ecdh(
		stse_ecc_key_type_t key_type,
		const PLAT_UI8 *pPubKey,
		const PLAT_UI8 *pPrivKey,
		PLAT_UI8       *pSharedSecret)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_aes_cmac_init (const PLAT_UI8 	*pKey,
		PLAT_UI16 		key_length,
		PLAT_UI16 		exp_tag_size)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_aes_cmac_append(PLAT_UI8* pInput,
		PLAT_UI16 lenght)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_aes_cmac_compute_finish(PLAT_UI8* pTag, PLAT_UI8* pTagLen)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_aes_cmac_verify_finish(PLAT_UI8* pTag)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_aes_cmac_compute(const PLAT_UI8 *pPayload,
		PLAT_UI16 		payload_length,
		const PLAT_UI8 	*pKey,
		PLAT_UI16 		key_length,
		PLAT_UI16 		exp_tag_size,
		PLAT_UI8 		*pTag,
		PLAT_UI16 		*pTag_length)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}
stse_ReturnCode_t stse_platform_aes_cmac_verify(const PLAT_UI8 *pPayload,
		PLAT_UI16 		payload_length,
		const PLAT_UI8 	*pKey,
		PLAT_UI16 		key_length,
		const PLAT_UI8 	*pTag,
		PLAT_UI16 		tag_length)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_aes_ccm_enc(const PLAT_UI8 *pPlaintext,
		PLAT_UI16 		plaintext_length,
		const PLAT_UI8 	*pKey,
		PLAT_UI16  		key_length,
		const PLAT_UI8 	*pNonce,
		PLAT_UI16  		nonce_length,
		const PLAT_UI8 	*pAssocData,
		PLAT_UI16  		assocData_length,
		PLAT_UI8       	*pEncryptedtext,
		PLAT_UI16 		*pEncryptedtext_length,
		PLAT_UI8       	*pTag,
		PLAT_UI16  		tag_length)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_aes_ccm_dec(const PLAT_UI8 *pEncryptedtext, PLAT_UI16 encryptedtext_length,
		const PLAT_UI8 *pTag,
		PLAT_UI16 tag_length,
		const PLAT_UI8 *pKey,
		PLAT_UI16 key_length,
		const PLAT_UI8 *pNonce,
		PLAT_UI16 nonce_length,
		const PLAT_UI8 *pAssocData,
		PLAT_UI16 assocData_length,
		const PLAT_UI8 *pPlaintext,
		PLAT_UI16 plaintext_length)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_aes_cbc_enc(const PLAT_UI8 *pPlaintext,
		PLAT_UI16  plaintext_length,
		PLAT_UI8 *pInitial_value,
		const PLAT_UI8 *pKey,
		PLAT_UI16  key_length,
		PLAT_UI8  *pEncryptedtext,
		PLAT_UI16 *pEncryptedtext_length)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_aes_cbc_dec(const PLAT_UI8 *pEncryptedtext,
		PLAT_UI16  encryptedtext_length,
		PLAT_UI8 *pInitial_value,
		const PLAT_UI8 *pKey,
		PLAT_UI16  key_length,
		PLAT_UI8  *pPlaintext,
		PLAT_UI16 *pPlaintext_length)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_aes_ecb_enc(const PLAT_UI8 *pPlaintext,
		PLAT_UI16  plaintext_length,
		const PLAT_UI8 *pKey,
		PLAT_UI16  key_length,
		PLAT_UI8  *pEncryptedtext,
		PLAT_UI16 *pEncryptedtext_length)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_aes_ecb_dec(const PLAT_UI8 *pEncryptedtext,
		PLAT_UI16  encryptedtext_length,
		const PLAT_UI8 *pKey,
		PLAT_UI16  key_length,
		PLAT_UI8  *pPlaintext,
		PLAT_UI16 *pPlaintext_length)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_nist_kw_encrypt(PLAT_UI8 *pPayload, PLAT_UI32 payload_length,
												PLAT_UI8 *pKey,		PLAT_UI8 key_length,
												PLAT_UI8 *pOutput, 	PLAT_UI32 *pOutput_length)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_hmac_sha256_compute(PLAT_UI8 *pSalt, PLAT_UI16 salt_length,
											 PLAT_UI8 *pInput_keying_material, PLAT_UI16 input_keying_material_length,
											 PLAT_UI8 *pInfo, PLAT_UI16 info_length,
											 PLAT_UI8 *pOutput_keying_material, PLAT_UI16 output_keying_material_length)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_hmac_sha256_extract(PLAT_UI8 *pSalt, PLAT_UI16 salt_length,
											 PLAT_UI8 *pInput_keying_material, PLAT_UI16 input_keying_material_length,
											 PLAT_UI8 *pPseudorandom_key, PLAT_UI16 pseudorandom_key_expected_length)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}

stse_ReturnCode_t stse_platform_hmac_sha256_expand(PLAT_UI8  *pPseudorandom_key, PLAT_UI16 pseudorandom_key_length,
											PLAT_UI8  *pInfo, PLAT_UI16 info_length,
											PLAT_UI8  *pOutput_keying_material, PLAT_UI16 output_keying_material_length)
{
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
}
