#if defined (CONFIG_ENABLE_LALU_AES)

#ifndef MBEDTLS_ALLOW_PRIVATE_ACCESS
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif
#include "mbedtls/cipher.h"
#include "mbedtls/aes.h"
#include "mbedtls/error.h"
#include "mbedtls/gcm.h"
#include "mbedtls/cmac.h"
#include "mbedtls/ccm.h"
#include "lalu_dmac.h"

#ifndef AES_CH_NUM
#define AES_CH_NUM  0
#endif

#define DMA_AES_MAX_BLOCK_SIZE  536870911u

#define LALU_AES_BLOCK_SIZE     16

#define AES_INTR_STATUS_OFF     0xEE0
#define SLAVE_MODE  0
#define DMA_MODE    1

#define AES_DECRYPT MBEDTLS_AES_DECRYPT
#define AES_ENCRYPT MBEDTLS_AES_ENCRYPT

#define XTS_KEY_1   0x10
#define XTS_KEY_2   0x11

#define LALU_ERR_AES_BAD_INPUT_DATA         MBEDTLS_ERR_AES_BAD_INTPUT_DATA
#define LALU_ERR_AES_INVALID_KEY_LENGTH     MBEDTLS_ERR_AES_INVALID_KEY_LENGTH 
#define LALU_ERR_AES_INVALID_INPUT_LENGTH   MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH

#define LALU_BYTE_0(x)  ((uint8_t) ((x)&0xff))
#define LALU_BYTE_1(x)  ((uint8_t) (((x) >> 8) &0xff))
#define LALU_BYTE_2(x)  ((uint8_t) (((x) >> 16) &0xff))
#define LALU_BYTE_3(x)  ((uint8_t) (((x) >> 24) &0xff))
#define LALU_BYTE_4(x)  ((uint8_t) (((x) >> 32) &0xff))
#define LALU_BYTE_5(x)  ((uint8_t) (((x) >> 40) &0xff))
#define LALU_BYTE_6(x)  ((uint8_t) (((x) >> 48) &0xff))
#define LALU_BYTE_7(x)  ((uint8_t) (((x) >> 56) &0xff))

#define AES_CONFIG_MASK             (0xfffffc60)
#define AES_CONFIG_DMA_MODE         BIT(0)
#define AES_CONFIG_ENCRYPT          BIT(7)
#define AES_CONFIG_FIRST_BLK        BIT(8)
#define AES_CONFIG_DE_KEY_GEN       BIT(9)
#define AES_CONFIG_AEAD_LAST_BLK    BIT(16)
#define AES_CONFIG_MAC_LAST_BLK     BIT(17)

struct lalu_aes_core_regs {
    struct {
        volatile uint32_t cpu_datain[4];
        volatile uint32_t cpu_dataout[4];
        volatile uint32_t key_de_out[8];
        volatile uint32_t key[8];
        volatile uint32_t iv[4];
        volatile uint32_t config;
        volatile uint32_t cipher_len;
        volatile uint32_t gmac_len_1;
        volatile uint32_t gmac_len_0;
        volatile uint32_t tag[4];
        volatile uint32_t ghash_key[4];
        volatile uint32_t byte_swap_disable;
    } ch_aes[16];
};

struct lalu_aes_int_and_constant_regs {
    volatile uint32_t aes_int_chn;
    volatile uint32_t reserved_0;
    volatile uint32_t reserved_1;
    volatile uint32_t reserved_2;
    struct {
        volatile uint32_t raw_aes;
        volatile uint32_t mask_aes;
        volatile uint32_t status_aes;
        volatile uint32_t clear_aes;
    } ch_aes[16];
    volatile uint32_t aes_chn_en;
    volatile uint32_t de_en_circuit;
    volatile uint32_t gcm_dou_circuit;
    volatile uint32_t date;
};
    
    

enum lalu_aes_config_blk{
    FIRST_BLK = 0,
    AEAD_LAST_BLK,
    MAC_LAST_BLK,
    CLEAR_FIRST_BLK,
    CLEAR_AEAD_LAST_BLK,
    CLEAR_MAC_LAST_BLK,
};

int lalu_set_hw_init(void *aes_base_address, void *dmac_base_address, void *aes_key_mgt_base);
int lalu_set_aes_blk(int aes_config_blk);
void lalu_set_aes_config(int dma_mode, int cipher_mode, int encrypt);
int lalu_aes_dmac_operation(uint32_t block_ts, uint32_t input, uint32_t output, int aes_config_blk);
int lalu_aes_slave_mode_operation(int cipher_mode, int set_last, int encrypt);
int lalu_aes_dma_mode_operation(const unsigned char *input, 
                                size_t input_length,
                                const unsigned char *output,
                                int cipher_mode,
                                int encrypt,
                                int aes_config_blk,
                                uint32_t *left);

int lalu_gcm_setkey(mbedtls_gcm_context *ctx,
                    mbedtls_cipher_id_t cipher,
                    const unsigned char *key,
                    unsigned int keybits);
                    
int lalu_gcm_starts(mbedtls_gcm_context *ctx, 
                    int mode, 
                    const unsigned char *iv, 
                    size_t iv_len);

int lalu_gcm_update_ad(mbedtls_gcm_context *ctx, 
                    const unsigned char *add, 
                    size_t add_len);
                    
int lalu_gcm_update(mbedtls_gcm_context *ctx,
                    const unsigned char *input , size_t input_length,
                    unsigned char *output, size_t output_size,
                    size_t *output_length);
                    
int lalu_gcm_finish(mbedtls_gcm_context *ctx,
                    unsigned char *output, size_t output_size,
                    size_t *output_length,
                    unsigned char *tag, size_t tag_len);
                    
#endif  /* CONFIG_ENABLE_LALU_AES */
