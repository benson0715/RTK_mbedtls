#ifndef __LALU_PKE_H__
#define __LALU_PKE_H__

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CONFIG_ENABLE_LALU_PKE_RSA) || defined(CONFIG_ENABLE_LALU_PKE_ECDSA)
// #define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls/bignum.h"
#include <stdbool.h>
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"

#define PKE_REG_OFF							0x0ul
#define PKE_MMEM_OFF						0x10000ul
#define PKE_TMEM_OFF						0x20000ul
#define PKE_IMEM_OFF						0x30000ul
#define PKE_REG_BASE						(0x40080000UL + PKE_REG_OFF)
#define PKE_MMEM_BASE						(0x40080000UL + PKE_MMEM_OFF)
#define PKE_TMEM_BASE						(0x40080000UL + PKE_TMEM_OFF)

/* Engine control register */
#ifndef BIT
#define BIT(x)								(1 << (x))
#endif

#define ENGINE_HASH_READY					BIT(31)
#define ENGINE_START_MCU					BIT(30)
#define ENGINE_OP(x)						(x << 6)
#define ENGINE_RRMODN(x)					(x << 24)
#define ENGINE_KEY_SIZE(x)					(x << 8)
#define ENGINE_MODE_CURVE(x)				(x << 5)

/* Enging status register */
#define ENGINE_STATUS_MASK					0xFE
#define ENGINE_STATUS_OP_FINISH				BIT(0)
#define ENGINE_STATUS_PRIME_CHK_ERR			BIT(1)
#define ENGINE_STATUS_RMOD_FAILED			BIT(2)
#define ENGINE_STATUS_ECC_ODD_POINT			BIT(3)
#define ENGINE_STATUS_ECC_Z					BIT(4)
#define ENGINE_STATUS_MOD_INV_FAILED		BIT(5)
#define ENGINE_STATUS_N_IN_MESSAGE			BIT(6)
#define ENGINE_STATUS_NO_VALID_EXP			BIT(7)

struct lalu_pke_reg {
	volatile uint32_t ctrl;
	volatile uint32_t cpu_ctrl;
	volatile uint32_t status;
	volatile uint32_t intr_mask;
	volatile uint32_t ctrl2;
	volatile uint32_t swap_base_addr;
	volatile uint32_t reserved0;
	volatile uint32_t version_number;
	volatile uint32_t reserved1[3];
	volatile uint32_t lfsr_seed;
	volatile uint32_t reserved2;
	volatile uint32_t pke_mutex;
	volatile uint32_t pke_mutex_overwrite;
};

int lalu_pke_init(void);

#if defined(CONFIG_ENABLE_LALU_PKE_RSA)
/* RSA reg */
#define RSA_N_OFF							0x0ul
#define RSA_E_OFF							0x200ul
#define RSA_A_OFF							0x400ul
#define RSA_X_OFF							0x600ul

#define PKE_RSA_N							(PKE_MMEM_BASE + RSA_N_OFF)
#define PKE_RSA_E							(PKE_MMEM_BASE + RSA_E_OFF)
#define PKE_RSA_A							(PKE_MMEM_BASE + RSA_A_OFF)
#define PKE_RSA_X							(PKE_MMEM_BASE + RSA_X_OFF)

void lalu_mpi_read_engine(const mbedtls_mpi *X, uint32_t srcPtr, size_t bufLen);
void lalu_mpi_set_engine(const mbedtls_mpi *X, uint32_t dstPtr, size_t bufword);
int lalu_pke_rsa(const mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *E,
			const mbedtls_mpi *N, const mbedtls_mpi *_RR, size_t rsa_len);

#endif /* CONFIG_ENABLE_LALU_PKE_RSA */

#if defined(CONFIG_ENABLE_LALU_PKE_ECDSA)
#define BUFWORD								64
/* ECC Reg */
#define PKE_ECC_N						(PKE_MMEM_BASE + 0x0ul)
#define PKE_ECC_E						(PKE_MMEM_BASE + 0x040ul)
#define PKE_ECC_A						(PKE_MMEM_BASE + 0x080ul)
#define PKE_ECC_R						(PKE_MMEM_BASE + 0x0C0ul)
#define PKE_ECC_B						(PKE_MMEM_BASE + 0x100ul)
#define PKE_ECC_X						(PKE_MMEM_BASE + 0x140ul)
#define PKE_ECC_Y						(PKE_MMEM_BASE + 0x180ul)
#define PKE_ECC_Z						(PKE_MMEM_BASE + 0x1C0ul)
#define PKE_ECC_X_RESULT				(PKE_MMEM_BASE + 0x200ul)
#define PKE_ECC_Y_RESULT				(PKE_MMEM_BASE + 0x240ul)
#define PKE_ECC_Z_RESULT				(PKE_MMEM_BASE + 0x280ul)
#define PKE_ECC_RANDOM					(PKE_MMEM_BASE + 0x380ul)
#define PKE_ECC_ORDER					(PKE_MMEM_BASE + 0x400ul)
#define PKE_ECC_N_1_MOD_R				(PKE_MMEM_BASE + 0x600ul)
#define PKE_ECC_N_1_MOD_R_4096			(PKE_MMEM_BASE + 0x800ul)

/* General output arguments in TMEM instead of MMEM */
#define TMEM_RESULT_1					(PKE_TMEM_BASE + 0x0ul)
#define TMEM_RESULT_2					(PKE_TMEM_BASE + 0x40ul)

#define PKE_ECC_TMEM_P					(PKE_TMEM_BASE + 0x80ul)
#define PKE_ECC_TMEM_E					(PKE_TMEM_BASE + 0xC0ul)
#define PKE_ECC_TMEM_A					(PKE_TMEM_BASE + 0x100ul)
#define PKE_ECC_TMEM_B					(PKE_TMEM_BASE + 0x140ul)
#define PKE_ECC_TMEM_GX					(PKE_TMEM_BASE + 0x180ul)
#define PKE_ECC_TMEM_GY					(PKE_TMEM_BASE + 0x1C0ul)
#define PKE_ECC_TMEM_GZ					(PKE_TMEM_BASE + 0x200ul)
#define PKE_ECC_TMEM_PX					(PKE_TMEM_BASE + 0x240ul)
#define PKE_ECC_TMEM_PY					(PKE_TMEM_BASE + 0x280ul)
#define PKE_ECC_TMEM_K					(PKE_TMEM_BASE + 0x2C0ul)
#define PKE_ECC_TMEM_N					(PKE_TMEM_BASE + 0x300ul)
#define PKE_ECC_TMEM_R					(PKE_TMEM_BASE + 0x340ul)
#define PKE_ECC_TMEM_S					(PKE_TMEM_BASE + 0x3C0ul)
#define PKE_ECC_TMEM_H					(PKE_TMEM_BASE + 0x340ul)
/* Digested message */
#define PKE_ECC_TMEM_Z					(PKE_TMEM_BASE + 0x380ul)
#define PKE_ECC_TMEM_SBX				(PKE_TMEM_BASE + 0x440ul)
#define PKE_ECC_TMEM_SBY				(PKE_TMEM_BASE + 0x480ul)
/* R as signature verification output */
#define PKE_ECC_TMEM_RV					(PKE_TMEM_BASE + 0x540ul)
#define PKE_ECC_TMEM_T1					(PKE_TMEM_BASE + 0x580ul)
#define PKE_ECC_TMEM_T2					(PKE_TMEM_BASE + 0x680ul)
#define PKE_ECC_TMEM_EDDSA_R			(PKE_TMEM_BASE + 0x640ul)
#define PKE_ECC_TMEM_EDDSA_S			(PKE_TMEM_BASE + 0x6C0ul)
#define PKE_ECC_TMEM_RHAX				(PKE_TMEM_BASE + 0x740ul)
#define PKE_ECC_TMEM_RHAY				(PKE_TMEM_BASE + 0x780ul)
/* Length of digested message */
#define PKE_ECC_TMEM_Z_LENGTH			(PKE_TMEM_BASE + 0x7C4ul)

enum pke_curve_type {
	PKE_CURVE_TYPE_PRIME		=	0,
	PKE_CURVE_TYPE_BINARY		=	2,
	PKE_CURVE_TYPE_RSA			=	4,
	PKE_CURVE_TYPE_EDWARDS		=	6,
	PKE_CURVE_TYPE_MONTGOMERY	=	7,
	PKE_CURVE_TYPE_INVALID_1	=	1,
	PKE_CURVE_TYPE_INVALID_3	=	3,
	PKE_CURVE_TYPE_INVALID_5	=	5,
};

enum pke_entry {
	RTK_PUBKEY_ECC_MUL_NEW_ENTRY		= 0x00,
	RTK_PUBKEY_ECC_MUL_ENTRY			= 0x01,
	RTK_PUBKEY_MOD_MUL_ENTRY			= 0x02,
	RTK_PUBKEY_MOD_ADD_ENTRY			= 0x03,
	/* Previous RTK_PRTK_PUBKEY_N_INV_ENTRYUBKEY_Px_MOD_ENTRY */
	ECDSA_MUL_PRIVATE					= 0x04,
	RTK_PUBKEY_R_SQAR_ENTRY				= 0x05,
	RTK_PUBKEY_N_INV_ENTRY				= 0x06,
	RTK_PUBKEY_K_INV_ENTRY				= 0x07,
	RTK_PUBKEY_ECC_ADD_POINT_ENTRY		= 0x08,
	RTK_PUBKEY_ECC_POINT_CHECK_ENTRY	= 0x09,
	RTK_PUBKEY_SET_A_FROM_P_ENTRY		= 0x0A,
	RTK_PUBKEY_MOD_MUL_BIN_ENTRY		= 0x0B,
	/* Previout RTK_PUBKEY_MOD_ADD_BIN_ENTRY */
	RTK_PUBKEY_MOD_XOR_ENTRY			= 0x0C,
	RTK_PUBKEY_MOD_COMP_BIN_ENTRY		= 0x0D,
	RTK_PUBKEY_X_MOD_N_ENTRY			= 0x0E,
	RTK_PUBKEY_MOD_SUB_ENTRY			= 0x0F,
	/* Internally used, listed as placeholders */
	PKE_ENTRY_INTERNAL_0				= 0x10,
	RTK_PUBKEY_K_INV_BIN_ENTRY			= 0x11,
	/* Internally used, listed as place holders */
	PKE_ENTRY_INTERNAL_1				= 0x12,
	PKE_ENTRY_INTERNAL_2				= 0x13,
	PKE_ENTRY_INTERNAL_3				= 0x14,
	PKE_ENTRY_INTERNAL_4				= 0x15,
	PKE_ENTRY_INTERNAL_5				= 0x16,
	PKE_ENTRY_INTERNAL_6				= 0x17,
	SIMPLIFY_ECDSA_GEN					= 0x18,
	SIMPLIFY_ECDSA_SIGN					= 0x19,
	SIMPLIFY_ECDSA_VERIFY				= 0x1A,
	SIMPLIFY_EDDSA_GEN					= 0x1B,
	SIMPLIFY_EDDSA_SIGN_R				= 0x1C,
	SIMPLIFY_EDDSA_SIGN_S				= 0x1D,
	SIMPLIFY_EDDSA_VERIFY				= 0x1E,
};

static inline enum pke_curve_type get_pke_curve_type_from_mbedtls_ecp_group(mbedtls_ecp_group_id group_id)
{
	switch (group_id) {
		case MBEDTLS_ECP_DP_SECP192R1:
		case MBEDTLS_ECP_DP_SECP224R1:
		case MBEDTLS_ECP_DP_SECP256R1:
		case MBEDTLS_ECP_DP_SECP384R1:
		case MBEDTLS_ECP_DP_SECP521R1:
		case MBEDTLS_ECP_DP_BP256R1:
		case MBEDTLS_ECP_DP_BP384R1:
		case MBEDTLS_ECP_DP_BP512R1:
		case MBEDTLS_ECP_DP_SECP192K1:
		case MBEDTLS_ECP_DP_SECP224K1:
		case MBEDTLS_ECP_DP_SECP256K1:
			return PKE_CURVE_TYPE_PRIME;
#if defined(MBEDTLS_EC_BINARY_CURVE_ENABLED)
		case MBEDTLS_ECP_DP_SECT163K1:
		case MBEDTLS_ECP_DP_SECT233K1:
		case MBEDTLS_ECP_DP_SECT283K1:
		case MBEDTLS_ECP_DP_SECT409K1:
		case MBEDTLS_ECP_DP_SECT571K1:
		case MBEDTLS_ECP_DP_SECT163R2:
		case MBEDTLS_ECP_DP_SECT233R1:
		case MBEDTLS_ECP_DP_SECT283R1:
		case MBEDTLS_ECP_DP_SECT409R1:
		case MBEDTLS_ECP_DP_SECT571R1:
			return PKE_CURVE_TYPE_BINARY;
#endif /* MBEDTLS_EC_BINARY_CURVE_ENABLED */
		case MBEDTLS_ECP_DP_CURVE25519:
		case MBEDTLS_ECP_DP_CURVE448:
			return PKE_CURVE_TYPE_MONTGOMERY;
		default:
			return PKE_CURVE_TYPE_INVALID_1;
	}
}

int lalu_ecdsa_sign_simplified(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
		const mbedtls_mpi *d, mbedtls_mpi *k, mbedtls_mpi *e, const unsigned char *buf, size_t blen);
int lalu_ecdsa_verify_simplified(mbedtls_ecp_group *grp, mbedtls_mpi *e, size_t blen,
		const mbedtls_ecp_point *Q, const mbedtls_mpi *r, const mbedtls_mpi *s);
int lalu_ecp_mul_simplified(mbedtls_ecp_group *grp, mbedtls_ecp_point *R, const mbedtls_mpi *m, const mbedtls_ecp_point *P);
int lalu_ecdsa_x_mod_n(mbedtls_ecp_group *grp, mbedtls_mpi *r);
int lalu_pubkey_set_a_from_p(mbedtls_ecp_group *grp);
int pke_mpi_write_argument(uint32_t dstPtr, const mbedtls_mpi *point);
void pke_int_write_argument(uint32_t dstPtr, uint32_t value);
int pke_mpi_read_argument(mbedtls_mpi *mpi, char *label, uint32_t srcPtr, int bits);
void pke_set_register_to_one(uint32_t dstPtr);
void pke_set_register_to_zero(uint32_t dstPtr);
int pke_set_entry(int nbits, int pbits, enum pke_curve_type curve_type,
					bool r_sqr_ready, uint8_t sub_func_en, enum pke_entry entry);
int pke_wait_done(void);

#endif /* CONFIG_ENABLE_LALU_PKE_ECDSA */
#endif /* defined(CONFIG_ENABLE_LALU_PKE_RSA) || defined(CONFIG_ENABLE_LALU_PKE_ECDSA) */

#ifdef __cplusplus
}
#endif

#endif /* __LALU_PKE_H__ */