#ifndef __LALU_SHA2_H__
#define __LALU_SHA2_H__

#if defined(CONFIG_ENABLE_LALU_SHA2) || 1
#ifndef MBEDTLS_ALLOW_PRIVATE_ACCESS
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/md.h"
#include <stdbool.h>

#define LALU_ERR_SHA_BAD_INPUT_DATA -0x8000

#define MAX_BUS_TS_SIZE8    8191
#define MSIZE8_LOG2         6
#define MAX_BUS_TS_SIZE16   4095
#define MSIZE16_LOG2        7

#define HAMC_KEY_SIZE_MASK  0x300
#define HMAC_KEY_SIZE_256   BIT(9)
#define HMAX_KEY_SIZE_192   BIT(8)
#define HMAC_MODE_MASK      0x10

#define SHA2_CTRL_MASK          0xFFFFF310
#define SHA2_CTRL_LMOTS_MASK    0xFFFF7FFF

#define SHA2_CTRL_DIGEST_BYTE_SWAP_ENABLE   BIT(15)
#define SHA2_CTRL_TRUNCATED_256             BIT(11)
#define SHA2_CTRL_TRUNCATED_EN              BIT(10)
#define SHA2_CTRL_SLAVE_MODE                BIT(6)
#define SHA2_CTRL_ICG_ENABLE                BIT(5)
#define SHA2_CTRL_HMAC_MODE                 BIT(4)
#define SHA2_CTRL_DMA_MODE                  BIT(2)

#define SHA_MODE(n)     (n << 0)

#define SHA2_MAX_FIFO_SIZE      0x10
#define SHA2_STATUS_FIFO_MASK   0x1F
#define SHA2_STATUS_BUSY        BIT(28)

#define SHA2_BLK_CTRL_FIRST_BLK         BIT(0)
#define SHA2_BLK_CTRL_LAST_BLK          BIT(1)
#define SHA2_BLK_CTRL_END_SLAVE_INPUT   BIT(2)

typedef enum {
    SHA224 = 0,
    SHA256,
    SHA384,
    SHA512,
    SHA512_224,
    SHA512_256,
} lalu_sha2_mode_id;

#define GET_UINT64_WE(n,b,i)                    \
{                                               \
    (n) = ( (uint64_t) (b)[(i)      ] << 32)    \
          | ((uint64_t)(b)[(i) + 1  ]);         \
}

#define PUT_UINT64_WE(n,b,i) \
{   \
    (n)[i] = (uint32_t)(((b) >> 32) & 0xFFFFFFFF);  \
    (n)[i + 1] = (uint32_t)((b) & 0xFFFFFFFF);      \
}

struct lalu_sha2_core {
    volatile uint32_t ctrl;
    volatile uint32_t status;
    volatile uint32_t blk_ctrl;
    volatile uint32_t reserved;
    volatile uint32_t digest[16];
    volatile uint32_t fifo_data[4];
    volatile uint32_t hmac_key[8];
    volatile uint32_t hash_in_len[4];
    volatile uint32_t lms_config;
    volatile uint32_t lms_control;
    volatile uint32_t lms_key_id_0;
    volatile uint32_t lms_key_id_1;
    volatile uint32_t lms_key_id_2;
    volatile uint32_t lms_key_id_3;
    volatile uint32_t lms_index_q;
    volatile uint32_t lms_index_byte;
    volatile uint32_t reserved1[20];
    volatile uint32_t digest_alias[8];
    volatile uint32_t dma_hs_cfg;
    volatile uint32_t dma_hs_blk_ts;
    volatile uint32_t dma_hs_buf_byte;
    volatile uint32_t dma_hs_en;
    volatile uint32_t reserved2[16];
    volatile uint32_t lmots_sig_alias256_0;
    volatile uint32_t lmots_sig_alias256_1;
    volatile uint32_t lmots_sig_alias256_2;
    volatile uint32_t lmots_sig_alias256_3;
    volatile uint32_t lmots_sig_alias256_4;
    volatile uint32_t lmots_sig_alias256_5;
    volatile uint32_t lmots_sig_alias256_6;
    volatile uint32_t lmots_sig_alias256_7;
    volatile uint32_t reserved3[732];
    volatile uint32_t mutex_status;
    volatile uint32_t reserved4[187];
    volatile uint32_t config;
    volatile uint32_t reservbed5;
    volatile uint32_t version;
    volatile uint32_t date;
};
    
int lalu_sha2_hw_init(void *sha2_base_address, void *dmac_base_address);
void lalu_sha256_starts_ret(int is224);
int lalu_internal_sha256_process(mbedtls_sha256_context *ctx, const uint8_t data[64], uint32_t blk_size);
int lalu_internal_sha256_finish(mbedtls_sha256_context *ctx, const uint8_t data[64]);

void lalu_sha512_starts_ret(int is384);
int lalu_internal_sha512_process(mbedtls_sha512_context *ctx, const uint8_t data[128], uint32_t blk_size);
int lalu_internal_sha512_finish(mbedtls_sha512_context* ctx, const uint8_t data[128]);

#endif

#endif  /* __LALU_SHA2_H__ */
