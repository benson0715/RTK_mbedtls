#if defined(CONFIG_ENABLE_LALU_PKE_ECDSA)
#include <common.h>
#include "mbedtls/ecp.h"
#include "lalu_pke.h"

int lalu_ecp_mul_simplified(mbedtls_ecp_group *grp, mbedtls_ecp_point *R, const mbedtls_mpi *m, const mbedtls_ecp_point *P)
{
    int status = -1;
    mbedtls_mpi A;
    mbedtls_mpi_init(&A);

    pke_mpi_write_argument(PKE_ECC_TMEM_P, &grp->P);
    pke_mpi_write_argument(PKE_ECC_TMEM_E, m);

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

    pke_mpi_write_argument(PKE_ECC_TMEM_PX, &A);
    pke_mpi_write_argument(PKE_ECC_TMEM_PY, &grp->B);
    pke_mpi_write_argument(PKE_ECC_TMEM_PX, &grp->N);
    pke_mpi_write_argument(PKE_ECC_TMEM_A, &A);
    pke_mpi_write_argument(PKE_ECC_TMEM_B, &grp->B);
    pke_mpi_write_argument(PKE_ECC_TMEM_GX, &(P->X));
    pke_mpi_write_argument(PKE_ECC_TMEM_GY, &(P->Y));
    pke_set_register_to_one(PKE_ECC_TMEM_GZ);

    pke_set_entry(grp->nbits, grp->pbits, 
        get_pke_curve_type_from_mbedtls_ecp_group(grp->id), false, 0, SIMPLIFY_ECDSA_GEN);
    
    if ((status = pke_wait_done()) != 0) {
        goto cleanup;
    }

    pke_mpi_read_argument(&R->X, "public key X", PKE_ECC_TMEM_PX, grp->pbits);
    pke_mpi_read_argument(&R->Y, "public key Y", PKE_ECC_TMEM_PY, grp->pbits);
    mbedtls_mpi_lset(&R->Z, 1);

cleanup:
    mbedtls_mpi_free(&A);
    return status;
}

#endif /* CONFIG_ENABLE_LALU_PKE_ECDSA */