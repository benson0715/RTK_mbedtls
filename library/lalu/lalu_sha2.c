#include <stdio.h>
#if defined(CONFIG_ENABLE_LALU_SHA2) || 1
#include "lalu_sha2.h"
#include "lalu_dmac.h"

static volatile struct lalu_sha2_core *sha2_core;
extern volatile struct lalu_dmac_regs *dmac_map;

#ifndef SHA2_CH_NUM
#define SHA2_CH_NUM 0
#endif

int lalu_sha2_hw_init(void *sha2_base_address, void *dmac_base_address)    
{
    sha2_core = sha2_base_address;
    lalu_crypto_dma_init(dmac_base_address, SHA2_CH_NUM);
    
    return 0;
}

static void lalu_sha2_dmac_ctrl_setup(int isSHA512)
{
    lalu_dmac_set_trnas_width(SHA2_CH_NUM, dmac_src_dst, dmac_trans_width_8);
    lalu_dmac_set_msize(SHA2_CH_NUM, dmac_dst, dmac_msize_1);
    if (isSHA512) {
        lalu_dmac_set_msize(SHA2_CH_NUM, dmac_src, dmac_msize_16);
    } else {
        lalu_dmac_set_msize(SHA2_CH_NUM, dmac_src, dmac_msize_8);
    }
}

static void lalu_sha2_dmac_setup(int isSHA512)
{
    lalu_sha2_dmac_ctrl_setup(isSHA512);
    lalu_dmac_unmask_irq(SHA2_CH_NUM, dmac_irq_tfr);
}

#if defined (CONFIG_ENABLE_LALU_SHA2_MODE_SWITCH)
static void lalu_internal_sha256_restore_ctx(lalu_sha2_mode_id mode)
{
    sha2_core->ctrl = (sha2_core->ctrl & SHA2_CTRL_MASK) | SHA2_CTRL_ICG_ENABLE;
    
    switch(mode){
        case SHA224:
            sha2_core->ctrl |= SHA_MODE(0);
            lalu_sha2_dmac_ctrl_setup(0);
            break;
        case SHA256:
            sha2_core->ctrl |= SHA_MODE(1);
            lalu_sha2_dmac_ctrl_setup(0);
            break;
        case SHA384:
            sha2_core->ctrl |= SHA_MODE(2);
            lalu_sha2_dmac_ctrl_setup(1);
            break;
        case SHA512:
            sha2_core->ctrl |= SHA_MODE(3);
            lalu_sha2_dmac_ctrl_setup(1);
            break;
#if defined(CONFIG_ENABLE_LALU_SHA512_TRUNCATED)
        case SHA512_224:
            sha2_core->ctrl |= (SHA_MODE(3) | SHA2_CTRL_TRUNCATED_EN);
            sha2_core->ctrl &= ~SHA2_CTRL_TRUNCATED_256;
            lalu_sha2_dmac_ctrl_setup(1);
            break;
        case SHA512_256:
            sha2_core->ctrl |= (SHA_MODE(3) | SHA2_CTRL_TRUNCATED_EN | SHA2_CTRL_TRUNCATED_256);
            lalu_sha2_dmac_ctrl_setup(1);
            break;
#endif
        default:
            break;
    }


}

#endif

static int lalu_sha2_start_dma(uint32_t phy_addr, uint32_t dma_blk_ts)
{
    int ret = -1;
    lalu_dmac_set_ts(SHA2_CH_NUM, phy_addr, (uint32_t)NULL, dma_blk_ts);
    lalu_dmac_enable_channel(SHA2_CH_NUM);
    lalu_dmac_wait_done(SHA2_CH_NUM);

    return 0;
}

static int lalu_sha2_start_slave(void)
{
    sha2_core->ctrl |= SHA2_CTRL_SLAVE_MODE;
    sha2_core->blk_ctrl |= SHA2_BLK_CTRL_END_SLAVE_INPUT;
    
    while(sha2_core->status & SHA2_STATUS_BUSY);
    sha2_core->ctrl &= ~SHA2_CTRL_SLAVE_MODE;
    
    return 0;
}

static int lalu_sha2_calc_digest(const uint8_t data[64], uint32_t blk_size, int isSHA512)
{
    int ret = -1;
    uint32_t phy_addr;
    uint32_t max_bus_ts = MAX_BUS_TS_SIZE8;
    uint32_t msize_log = MSIZE8_LOG2;
    
    phy_addr = (uint32_t)(data);
    
    if (isSHA512) {
        max_bus_ts = MAX_BUS_TS_SIZE16;
        msize_log = MSIZE16_LOG2;
    }

    while(blk_size > 0) {
        if (blk_size > max_bus_ts) {
            lalu_sha2_start_dma(phy_addr, max_bus_ts << msize_log);
            
            phy_addr += max_bus_ts << msize_log;
            blk_size -= max_bus_ts;
        } else {
            lalu_sha2_start_dma(phy_addr, blk_size << msize_log);
            break;
        }
    }
    
    return 0;
}

int lalu_internal_sha256_finish(mbedtls_sha256_context* ctx, const uint8_t data[64])
{
    int i, ret = -1;
    uint32_t left;
    uint32_t phy_addr;
    
    phy_addr = (uint32_t)(data);
#if defined (CONFIG_ENABLE_LALU_SHA2_CTX_SWITCH)
#if defined (CONFIG_ENABLE_LALU_SHA2_MODE_SWITCH)
    int is224 = 0;
    lalu_sha2_mode_id mode;
    
#if defined(MBEDTLS_SHA224_C)
    is224 = ctx->is224;
#endif
    if (is224) {
        mode = SHA224;
    }else {
        mode = SHA256;
    }
    
    lalu_internal_sha256_restore_ctx(mode);
#endif
    for (i = 0; i < 8; i++) {
        sha2_core->digest[(i << 1)] = ctx->state[i];
        sha2_core->digest[(i << 1) + 1] = 0;
    }
#endif
    while(sha2_core->status & SHA2_STATUS_BUSY);
    sha2_core->blk_ctrl |= SHA2_BLK_CTRL_LAST_BLK;
    
    left = ctx->total[0] & 0x3f;
    
    if ((sha2_core->ctrl & SHA2_CTRL_HMAC_MODE) >> 4) {
        ctx->total[0] += 0x40;
        ctx->total[0] &= 0xFFFFFFFF;
        if (ctx->total[0] < 0x40) {
            ctx->total[1] += 1;
        }
    }

    sha2_core->hash_in_len[3] = ctx->total[0];
    sha2_core->hash_in_len[2] = ctx->total[1];
    sha2_core->hash_in_len[1] = 0x0;
    sha2_core->hash_in_len[0] = 0x0;
    
    if (left == 0) {
        lalu_sha2_start_slave();
    } else {
        lalu_sha2_start_dma(phy_addr, left);
    }

    while(sha2_core->status & SHA2_STATUS_BUSY);
    sha2_core->blk_ctrl &= ~SHA2_BLK_CTRL_LAST_BLK;
    
    for (i = 0; i < 8; i++) {
        ctx->state[i] = sha2_core->digest[(i << 1)];
    }

    return ret;
}


int lalu_internal_sha512_finish(mbedtls_sha512_context* ctx, const uint8_t data[128])
{
    int i, ret = -1;
    uint32_t left;
    uint32_t phy_addr;
    
    phy_addr = (uint32_t)(data);
    
#if defined (CONFIG_ENABLE_LALU_SHA2_CTX_SWITCH)
#if defined (CONFIG_ENABLE_LALU_SHA2_MODE_SWITCH)
    int is384 = 0;
    int is256 = 0;
    int is224 = 0;
    lalu_sha2_mode_id mode;
    
#if defined(MBEDTLS_SHA384_C)
    is384 = ctx->is384;
#endif
    
#if defined(CONFIG_ENABLE_LALU_SHA512_TURNCATED)
    is224 = ctx->is224;
    is256 = ctx->is256;
#endif    
    
    if (is384) {
        mode = SHA384;
    } else if (is256) {
        mode = SHA512_256;
    } else if (is224) {
        mode = SHA512_224;
    } else {
        mode = SHA256;
    }
    
    lalu_internal_sha256_restore_ctx(mode);
#endif
    for (i = 0; i < 8; i++) {
        PUT_UINT64_WE(sha2_core->digest, ctx->state[i], (i << 1));
    }
#endif

    while(sha2_core->status & SHA2_STATUS_BUSY);

    sha2_core->blk_ctrl |= SHA2_BLK_CTRL_LAST_BLK;
    
    left = ctx->total[0] & 0x7f;
    
    if ((sha2_core->ctrl & SHA2_CTRL_HMAC_MODE) >> 4) {
        ctx->total[0] += 0x80;
        if (ctx->total[0] < 0x80) {
            ctx->total[1] += 1;
        }
    }

    sha2_core->hash_in_len[3] = (ctx->total[0] >> 0) & 0xffffffff;
    sha2_core->hash_in_len[2] = (ctx->total[0] >> 32) & 0xffffffff;
    sha2_core->hash_in_len[1] = (ctx->total[1] >> 0) & 0xffffffff;
    sha2_core->hash_in_len[0] = (ctx->total[1] >> 32) & 0xffffffff;
    if (left == 0) {
        lalu_sha2_start_slave();
    } else {
        lalu_sha2_start_dma(phy_addr, left);
    }
    while(sha2_core->status & SHA2_STATUS_BUSY);
    sha2_core->blk_ctrl &= ~SHA2_BLK_CTRL_LAST_BLK;
    
    for (i = 0; i < 8; i++) {
        GET_UINT64_WE(ctx->state[i], sha2_core->digest, (i << 1))
    }
    
    return ret;
}

int lalu_internal_sha256_process(mbedtls_sha256_context *ctx, const uint8_t data[64], uint32_t blk_size)
{
    int ret;
    (void)ctx;

    ret = lalu_sha2_calc_digest(data, blk_size, 0);

#if defined(CONFIG_ENABLE_LALU_SHA2_CTX_SWITCH)
    for (int i = 0; i < 8; i++) {
        ctx->state[i] = sha2_core->digest[(i << 1)];
    }
#endif    
    return ret;
}
int lalu_internal_sha512_process(mbedtls_sha512_context *ctx, const uint8_t data[128], uint32_t blk_size)
{
    int ret;
    (void)ctx;

    ret = lalu_sha2_calc_digest(data, blk_size, 1);

    return ret;
}

void lalu_sha256_starts_ret(int is224)
{
    if (is224 == 0) {
        sha2_core->ctrl = (sha2_core->ctrl & SHA2_CTRL_MASK) | SHA_MODE(1) | SHA2_CTRL_ICG_ENABLE;
    } else {
        sha2_core->ctrl = (sha2_core->ctrl & SHA2_CTRL_MASK) | SHA_MODE(0) | SHA2_CTRL_ICG_ENABLE;
    }
    while(sha2_core->status & SHA2_STATUS_BUSY);
    sha2_core->blk_ctrl = (sha2_core->blk_ctrl | SHA2_BLK_CTRL_FIRST_BLK);
    lalu_sha2_dmac_setup(0);
}

void lalu_sha512_starts_ret(int is384)
{
    if (is384 == 0) {
        sha2_core->ctrl = (sha2_core->ctrl & SHA2_CTRL_MASK) | SHA_MODE(3) | SHA2_CTRL_ICG_ENABLE;
    } else {
        sha2_core->ctrl = (sha2_core->ctrl & SHA2_CTRL_MASK) | SHA_MODE(2) | SHA2_CTRL_ICG_ENABLE;
    }
    while(sha2_core->status & SHA2_STATUS_BUSY);
    sha2_core->blk_ctrl = (sha2_core->blk_ctrl | SHA2_BLK_CTRL_FIRST_BLK);
    lalu_sha2_dmac_setup(1);
}

#endif
