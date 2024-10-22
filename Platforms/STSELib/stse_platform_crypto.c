#include "stselib.h"

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
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
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
	stse_ReturnCode_t ret = STSE_PLATFORM_SERVICES_INIT_ERROR;
	/* TODO */
	return ret;
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
