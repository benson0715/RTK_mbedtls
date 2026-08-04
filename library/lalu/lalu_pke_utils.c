#if defined(CONFIG_ENABLE_LALU_PKE_RSA) || defined(CONFIG_ENABLE_LALU_PKE_ECDSA)

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "common.h"
#include "mbedtls/bignum.h"
#include "lalu_pke.h"

extern volatile int __is_hash_in_advance_enabled;
volatile struct lalu_pke_reg *ecc_reg = (struct lalu_pke_reg *)(0x40080000UL);

int lalu_pke_init(void) {
	/* Read PKE mutex register (0x34) for starting to write PKE register */
	volatile uint32_t value = ecc_reg->pke_mutex;
	// printf("PKE initialize mutex value = 0x%lx\n", value);
	return 0;
}
#if defined(CONFIG_ENABLE_LALU_PKE_ECDSA)

volatile uint32_t *tmem_reg = (volatile uint32_t *)0x400A0000UL;
volatile uint32_t *mmem_reg = (volatile uint32_t *)0x40090000UL;

extern int is_hash_in_advance_enabled;
/* 16 for default, 20 for ECC640 */
#define PKE_WORDS_PER_REGISTER 16
int pke_set_entry(int nbits, int pbits, enum pke_curve_type curve_type,
				  bool r_sqr_ready, uint8_t sub_func_en, enum pke_entry entry) 
{
	uint32_t ctrl_reg = 0;
	/* Abort early if the curve type is not supported */
	switch (curve_type) {
		case PKE_CURVE_TYPE_PRIME:
		case PKE_CURVE_TYPE_BINARY:
		case PKE_CURVE_TYPE_EDWARDS:
		case PKE_CURVE_TYPE_MONTGOMERY:
			break;
		default:
			printf("[ERROR] Curve type %d is not supported by pke_set_entry\n", curve_type);
			return -1;
	}

	/* Select bits from bits(p) or bits(n) */
	int bits = (
		entry == RTK_PUBKEY_ECC_MUL_NEW_ENTRY || entry == RTK_PUBKEY_ECC_MUL_ENTRY
		|| entry == RTK_PUBKEY_ECC_ADD_POINT_ENTRY || entry == RTK_PUBKEY_ECC_POINT_CHECK_ENTRY
		|| entry == SIMPLIFY_ECDSA_GEN || entry == SIMPLIFY_ECDSA_SIGN
		|| entry == SIMPLIFY_ECDSA_VERIFY || entry == SIMPLIFY_EDDSA_GEN
		|| entry == SIMPLIFY_EDDSA_SIGN_R || entry == SIMPLIFY_EDDSA_SIGN_S || entry == SIMPLIFY_EDDSA_VERIFY
	) ? pbits : nbits;
	if (entry == RTK_PUBKEY_ECC_MUL_NEW_ENTRY || entry == RTK_PUBKEY_ECC_MUL_ENTRY) {
		if (pbits < nbits) {
			bits = nbits;
		}
	}

	if (/* ECDSA: keyGen(x) sigGen(x) sigVer(x) */
		entry != SIMPLIFY_ECDSA_SIGN && entry != SIMPLIFY_ECDSA_VERIFY
		/* eCDSA: x */
		&& entry != SIMPLIFY_ECDSA_GEN && entry != SIMPLIFY_ECDSA_SIGN
		&& entry != SIMPLIFY_EDDSA_SIGN_S && entry != SIMPLIFY_EDDSA_VERIFY
		/* EdCH: prime(binary)(montgomery)(x) */
		&& curve_type != PKE_CURVE_TYPE_MONTGOMERY)
	/* DPA-defence: always resets some randomization values
	Internal-LFSR (bit 4) is set to provide this value internally */
	{
		sub_func_en |= BIT(2) | BIT(4);
	}

	if (/* ECDSA: keyGen(o) sigGen(o) sigVer(x) */
		entry != SIMPLIFY_ECDSA_VERIFY
		/* EdDSA: x */
		&& entry != SIMPLIFY_EDDSA_GEN && entry != SIMPLIFY_EDDSA_SIGN_R
		&& entry != SIMPLIFY_EDDSA_SIGN_S && entry != SIMPLIFY_EDDSA_VERIFY
		/* ECDH: prime/binary(o) (montgomery)(x) */
		&& curve_type != PKE_CURVE_TYPE_MONTGOMERY) 
	{
		sub_func_en |= BIT(3);
	}

	// Set ECC engine entry to TMEM[0]
	if (entry == RTK_PUBKEY_ECC_MUL_ENTRY) {
		*tmem_reg = RTK_PUBKEY_ECC_MUL_NEW_ENTRY;
	} else {
		*tmem_reg = entry;
	}
	
	// Clear finish status before going
	ecc_reg->status = 0;

	// Compose control register value
	ctrl_reg = ENGINE_KEY_SIZE(bits) | ENGINE_RRMODN(r_sqr_ready) |
				(sub_func_en | ENGINE_MODE_CURVE(curve_type)) | 
				/* Bit 30 : start PKE */
				ENGINE_START_MCU;

	// Bit 27: other functions than ECC/RSA
	// For ECDSA, only ECC_MUL is "ECC/RSA" (= set 0)
	// the vase other entries are "other functions" (= set 1)
	// The simplified ECDSA entries states [27] = 1 explicitly
	if (entry != RTK_PUBKEY_ECC_MUL_NEW_ENTRY && entry != RTK_PUBKEY_ECC_MUL_ENTRY) {
		ctrl_reg |= BIT(27);
	}

	// Bit 31: indicate hash already in simplified flow
	// So PKE won't pause for hash half way
	if (__is_hash_in_advance_enabled) {
		ctrl_reg |= 0x80000000ul;
	}

	ecc_reg->ctrl = ctrl_reg;
	return 0;
}

int pke_wait_done(void) {
	uint32_t status;

	// Polling
	do {
		status = ecc_reg->status;
	} while (!(ecc_reg->status & ENGINE_STATUS_OP_FINISH));

	// Clear finish status
	ecc_reg->status = 0;

	return (status & ENGINE_STATUS_MASK);
}

int pke_mpi_write_argument (uint32_t dstPtr, const mbedtls_mpi *point) \
{
	volatile uint32_t *target_register =  (volatile uint32_t *)(dstPtr);
	bool is_32_bit = (sizeof(mbedtls_mpi_uint) == 4);
	int words_in_point = point->n * (is_32_bit ? 1 : 2);

	if (words_in_point > PKE_WORDS_PER_REGISTER) {
		return -1;
	}

	for (int i = 0; i < PKE_WORDS_PER_REGISTER; i++) {
		if (i < words_in_point && is_32_bit) {
			target_register[i] = point->p[i];
		} else if (i < words_in_point && !is_32_bit){
			int offset  = ((i % 2 == 0) ? 0 : 32);
			target_register[i] = (
				(uint32_t)((point->p[i / 2] >> offset) & 0xFFFFFFFF)
			);
		} else {
			target_register[i] = 0;
		}
	}

	return 0;
}

void pke_int_write_argument(uint32_t dstPtr, uint32_t value) {
	volatile uint32_t *target_register = (volatile uint32_t *)(dstPtr);
	*target_register = value;
}

int pke_mpi_read_argument(mbedtls_mpi *mpi, char *label, uint32_t srcPtr, int bits)
{
	int status;
	uint8_t buffer[BUFWORD];
	volatile uint32_t *target_register = (volatile uint32_t *)(srcPtr);

	int number_of_registers = (bits + 31) / 32;
	int number_of_bytes = number_of_registers * 4;

	for (int i = 0; i < BUFWORD; i++) {
		if (i < number_of_bytes) {
			buffer[(BUFWORD - 1) - i] = (uint8_t)(target_register[i / 4] >> ((i % 4) * 8));
		} else {
			buffer[(BUFWORD - 1) - i] = 0;
		}
	}

	if ((status = mbedtls_mpi_read_binary(mpi, buffer, BUFWORD)) != 0) {
		// printf("Failed read PKE register at address %02lx into mbedtls bignum %s\n", srcPtr, label);
	}

	return status;
}

void pke_set_register_to_one(uint32_t dstPtr) {
	volatile uint32_t *target_register = (volatile uint32_t *)(dstPtr);
	for (int i = 0; i < PKE_WORDS_PER_REGISTER; i++) {
		target_register[i] = (i == 0) ? 1 : 0;
	}
}

void pke_set_register_to_zero(uint32_t dstPtr) {
	volatile uint32_t *target_register = (volatile uint32_t *)(dstPtr);
	for (int i = 0; i < PKE_WORDS_PER_REGISTER; i++) {
		target_register[i] = 0;
	}
}

#endif /* CONFIG_ENABLE_LALU_PKE_ECDSA */
#endif /* CONFIG_ENABLE_LALU_PKE_ECDSA || CONFIG_ENABLE_LALU_PKE_RSA*/
