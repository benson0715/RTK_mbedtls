#if defined(CONFIG_ENABLE_LALU_PKE_ECDSA)
#include "lalu_pke.h"
volatile int __is_hash_in_advance_enabled = 0;

int derive_mpi(const mbedtls_ecp_group *grp, mbedtls_mpi *x, const unsigned char *buf, size_t blen);

int lalu_ecdsa_x_mod_n(mbedtls_ecp_group *grp, mbedtls_mpi *r)
{
	int status = -1;
	pke_mpi_write_argument(PKE_ECC_N, &grp->N);
	pke_set_entry(grp->nbits, grp->pbits, 
				/* Always PRIME for N */
				PKE_CURVE_TYPE_PRIME, true, 1, RTK_PUBKEY_X_MOD_N_ENTRY);
	if ((status = pke_wait_done()) != 0) {
		return status;
	}

	// Read the result
	pke_mpi_read_argument(r, "R", TMEM_RESULT_1, grp->pbits);

	return status;
}

int lalu_pubkey_set_a_from_p(mbedtls_ecp_group *grp)
{
	int status = -1;
	mbedtls_mpi A;
	mbedtls_mpi_init(&A);

	pke_mpi_write_argument(PKE_ECC_TMEM_P, &grp->P);

	if (grp->A.p == NULL) {
		pke_mpi_write_argument(PKE_ECC_N, &grp->P);
		pke_set_entry(grp->nbits, grp->pbits, 
			get_pke_curve_type_from_mbedtls_ecp_group(grp->id), false, 1, RTK_PUBKEY_SET_A_FROM_P_ENTRY);
		
		if ((status = pke_wait_done()) != 0) {
			goto cleanup;
		}
		pke_mpi_read_argument(&A, "A", TMEM_RESULT_1, grp->pbits);
	} else {
		mbedtls_mpi_copy(&A, &grp->A);
	}
	pke_mpi_write_argument(PKE_ECC_TMEM_A, &A);

cleanup:
	mbedtls_mpi_free(&A);
	return status;
}

int lalu_ecdsa_sign_simplified(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s, const mbedtls_mpi *d, 
								mbedtls_mpi *k, mbedtls_mpi *e, const unsigned char *buf, size_t blen)
{
	int status = -1;
	if ((status = lalu_pubkey_set_a_from_p(grp)) != 0) {
		return status;
	}

	pke_mpi_write_argument(PKE_ECC_TMEM_E, d);
	pke_mpi_write_argument(PKE_ECC_TMEM_B, &grp->B);
	pke_mpi_write_argument(PKE_ECC_TMEM_GX, &grp->G.X);
	pke_mpi_write_argument(PKE_ECC_TMEM_GY, &grp->G.Y);
	pke_set_register_to_one(PKE_ECC_TMEM_GZ);
	pke_mpi_write_argument(PKE_ECC_TMEM_K, k);
	pke_mpi_write_argument(PKE_ECC_TMEM_N, &grp->N);

	if ((status = derive_mpi(grp, e, buf, blen)) != 0) {
		return status;
	}

	pke_mpi_write_argument(PKE_ECC_TMEM_Z, e);
	pke_int_write_argument(PKE_ECC_TMEM_Z_LENGTH, blen * 8);
	
	__is_hash_in_advance_enabled = 1;
	pke_set_entry(grp->nbits, grp->pbits, 
				get_pke_curve_type_from_mbedtls_ecp_group(grp->id), false, 0, SIMPLIFY_ECDSA_SIGN);
	if ((status = pke_wait_done()) != 0) {
		return status;
	}
	__is_hash_in_advance_enabled = 0;

	pke_mpi_read_argument(r, "r", PKE_ECC_TMEM_R, grp->pbits);
	pke_mpi_read_argument(s, "s", PKE_ECC_TMEM_S, grp->pbits);

	return 0;
}

int lalu_ecdsa_verify_simplified(mbedtls_ecp_group *grp, mbedtls_mpi *e, size_t blen, const mbedtls_ecp_point *Q,
									const mbedtls_mpi *r, const mbedtls_mpi *s)
{
	int status = -1;
	mbedtls_mpi rq;
	mbedtls_mpi_init(&rq);

	if ((status = lalu_pubkey_set_a_from_p(grp)) != 0) {
		goto cleanup;
	}

	pke_mpi_write_argument(PKE_ECC_TMEM_B, &grp->B);
	pke_mpi_write_argument(PKE_ECC_TMEM_GX, &grp->G.X);
	pke_mpi_write_argument(PKE_ECC_TMEM_GY, &grp->G.Y);
	pke_set_register_to_one(PKE_ECC_TMEM_GZ);
	pke_mpi_write_argument(PKE_ECC_TMEM_PX, &(Q->X));
	pke_mpi_write_argument(PKE_ECC_TMEM_PY, &(Q->Y));
	pke_mpi_write_argument(PKE_ECC_TMEM_N, &grp->N);
	pke_mpi_write_argument(PKE_ECC_TMEM_R, r);
	pke_mpi_write_argument(PKE_ECC_TMEM_S, s);

	pke_mpi_write_argument(PKE_ECC_TMEM_Z, e);
	pke_int_write_argument(PKE_ECC_TMEM_Z_LENGTH, blen * 8);

	__is_hash_in_advance_enabled = 1;
	pke_set_entry(grp->nbits, grp->pbits, 
				get_pke_curve_type_from_mbedtls_ecp_group(grp->id), false, 1, SIMPLIFY_ECDSA_VERIFY);
	
	if ((status = pke_wait_done()) != 0) {
		goto cleanup;
	}

	pke_mpi_read_argument(&rq, "rQ", PKE_ECC_TMEM_RV, grp->pbits);
	status = mbedtls_mpi_cmp_mpi(&rq, r);

cleanup:
	__is_hash_in_advance_enabled = 0;
	mbedtls_mpi_free(&rq);
	return status;
}

#endif /* CONFIG_ENABLE_LALU_PKE_ECDSA */
