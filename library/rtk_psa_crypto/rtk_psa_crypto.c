#include <psa/nsc_api_table.h>
#include <psa/rtk_psa_crypto.h>

static const NSC_API_FnTbl_t *api = (const NSC_API_FnTbl_t *)NSC_API_TABLE_ADDR;

static uint8_t heap_ptr[20];
__attribute__((aligned(4))) static uint8_t mbedtls_mem_buf[0x800];

psa_status_t rtk_psa_crypto_init(void)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	status = api->crypto_init((uint32_t)heap_ptr, mbedtls_mem_buf, sizeof(mbedtls_mem_buf));

	return status;
}

psa_status_t rtk_psa_hash_abort(psa_algorithm_t alg, uint8_t *sha_ctx)
{
	if (alg >= SHA_MAX_NUM) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	api->sha_free(alg, sha_ctx);

	return PSA_SUCCESS;
}

psa_status_t rtk_psa_hash_setup(psa_algorithm_t alg, uint8_t *sha_ctx)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	if (alg >= SHA_MAX_NUM) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	status = api->sha_init(alg, sha_ctx);
	if (status != 0) {
		return status;
	}

	status = api->sha_starts(alg, sha_ctx);

	return status;
}

psa_status_t rtk_psa_hash_update(psa_algorithm_t alg, const uint8_t *input, size_t input_len,
				 uint8_t *sha_ctx)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	if (alg >= SHA_MAX_NUM) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	status = api->sha_update(alg, input, input_len, sha_ctx);

	return status;
}

psa_status_t rtk_psa_hash_finish(psa_algorithm_t alg, uint8_t *hash, uint8_t *sha_ctx)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	if (alg >= SHA_MAX_NUM) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	status = api->sha_finish(alg, hash, sha_ctx);
	api->sha_free(alg, sha_ctx);

	return status;
}

psa_status_t rtk_psa_hash_compute(psa_algorithm_t alg, const uint8_t *input, size_t input_len,
				  uint8_t *hash)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	if (alg >= SHA_MAX_NUM) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	status = api->sha(alg, input, input_len, hash);

	return status;
}

psa_status_t rtk_psa_mac_compute(psa_algorithm_t alg, const uint8_t *key, size_t key_len,
				 const uint8_t *input, size_t input_len, uint8_t *hmac_hash)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	if (alg >= SHA_MAX_NUM) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	status = api->hmac(alg, key, key_len, input, input_len, hmac_hash);

	return status;
}

psa_status_t rtk_psa_ecdsa_genkey(psa_algorithm_t alg, uint8_t *pk, uint8_t *sk, uint8_t *seed,
				  size_t seed_len)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	if (alg >= ECDSA_CURVE_MAX_NUM) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	status = api->ecdsa_genkey(alg, pk, sk, seed, seed_len);

	return status;
}

psa_status_t rtk_psa_ecdsa_sign(psa_algorithm_t alg, const uint8_t *sk, const uint8_t *hash,
				size_t hash_len, uint8_t *sig, size_t *sig_len, size_t sig_size)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	if (alg >= ECDSA_CURVE_MAX_NUM) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	status = api->ecdsa_sign(alg, sk, hash, hash_len, sig, sig_len, sig_size);

	return status;
}

psa_status_t rtk_psa_ecdsa_verify(psa_algorithm_t alg, const uint8_t *pk, const uint8_t *hash,
				  size_t hash_len, const uint8_t *sig, size_t sig_len)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	if (alg >= ECDSA_CURVE_MAX_NUM) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	status = api->ecdsa_verify(alg, pk, hash, hash_len, sig, sig_len);

	return status;
}

psa_status_t rtk_psa_ecdsa_sign_raw(psa_algorithm_t alg, const uint8_t *sk, const uint8_t *hash,
				    size_t hash_len, uint8_t *r_buf, uint8_t *s_buf)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	if (alg >= ECDSA_CURVE_MAX_NUM) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	status = api->ecdsa_sign_raw(alg, sk, hash, hash_len, r_buf, s_buf);

	return status;
}

psa_status_t rtk_psa_ecdsa_verify_raw(psa_algorithm_t alg, const uint8_t *pk, const uint8_t *hash,
				      size_t hash_len, const uint8_t *sig)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	if (alg >= ECDSA_CURVE_MAX_NUM) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	status = api->ecdsa_verify_raw(alg, pk, hash, hash_len, sig);

	return status;
}

psa_status_t rtk_psa_ecdh_gen_shared_secret(psa_algorithm_t alg, const uint8_t *pk,
					    const uint8_t *sk, uint8_t *ss)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	if (alg >= ECDSA_CURVE_MAX_NUM) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	status = api->ecdh_gen_shared_secret(alg, pk, sk, ss);

	return status;
}

psa_status_t rtk_psa_aes_gcm_encrypt(uint8_t *key, size_t key_len, uint8_t *iv, size_t iv_len,
				     uint8_t *add, size_t add_len, uint8_t *input, size_t ilen,
				     uint8_t *output, uint8_t *tag, size_t tag_len)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	status = api->aes_gcm_encrypt(key, key_len, iv, iv_len, add, add_len, input, ilen, output,
				      tag, tag_len);

	return status;
}

psa_status_t rtk_psa_aes_gcm_decrypt(uint8_t *key, size_t key_len, uint8_t *iv, size_t iv_len,
				     uint8_t *add, size_t add_len, uint8_t *input, size_t ilen,
				     uint8_t *output, uint8_t *tag, size_t tag_len)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	status = api->aes_gcm_decrypt(key, key_len, iv, iv_len, add, add_len, input, ilen, output,
				      tag, tag_len);

	return status;
}

psa_status_t rtk_psa_mldsa_genkey(psa_algorithm_t alg, uint8_t *pk, uint8_t *sk, uint8_t *seed)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	status = api->mldsa_genkey(alg, pk, sk, seed);

	return status;
}

psa_status_t rtk_psa_mldsa_sign(psa_algorithm_t alg, uint8_t *sig, const uint8_t *msg,
				size_t msg_len, const uint8_t *ctx, uint8_t ctx_len,
				const uint8_t *sk, const uint8_t *rnd)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	size_t dummy_sig_len = 0;

	status = api->mldsa_sign(alg, sig, &dummy_sig_len, msg, msg_len, ctx, ctx_len, sk, rnd);

	return status;
}

psa_status_t rtk_psa_mldsa_verify(psa_algorithm_t alg, uint8_t *sig, const uint8_t *msg,
				  size_t msg_len, const uint8_t *ctx, uint8_t ctx_len,
				  const uint8_t *pk)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	size_t dummy_sig_len = 0;

	status = api->mldsa_verify(alg, sig, dummy_sig_len, msg, msg_len, ctx, ctx_len, pk);

	return status;
}

psa_status_t rtk_psa_kyber_genkey(psa_algorithm_t alg, uint8_t *pk, uint8_t *sk,
				  const uint8_t *coins)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	status = api->kyber_genkey(alg, pk, sk, coins);

	return status;
}

psa_status_t rtk_psa_kyber_kem_enc(psa_algorithm_t alg, uint8_t *ct, uint8_t *ss, const uint8_t *pk,
				   const uint8_t *coins)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	status = api->kyber_kem_enc(alg, ct, ss, pk, coins);

	return status;
}

psa_status_t rtk_psa_kyber_kem_dec(psa_algorithm_t alg, uint8_t *ss, const uint8_t *ct,
				   const uint8_t *sk)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	status = api->kyber_kem_dec(alg, ss, ct, sk);

	return status;
}
