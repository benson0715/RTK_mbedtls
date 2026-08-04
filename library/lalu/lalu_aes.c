#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#if defined(CONFIG_ENABLE_LALU_AES)
#include "lalu_aes.h"
#include "lalu_key_mgr.h"
#include "mbedtls/platform.h"

extern struct lalu_dmac_regs *dmac_map;
uint32_t aes_config = 0;
volatile struct lalu_aes_core_regs *aes_core_map;
volatile struct lalu_aes_int_and_constant_regs *dmac_aes_int_map;
static volatile struct lalu_key_manager_regs *aes_key_mgt_map;

int lalu_set_hw_init(void *aes_base_address, void *dmac_base_address, void *aes_key_mgt_base)
{
    aes_core_map = aes_base_address;
    aes_key_mgt_map = aes_key_mgt_base;
    dmac_aes_int_map = (void *)((uint8_t *)aes_base_address + AES_INTR_STATUS_OFF);
    
    dmac_aes_int_map->ch_aes[AES_CH_NUM].mask_aes = 0x0;
    
    lalu_crypto_dma_init(dmac_base_address, AES_CH_NUM);
    lalu_dmac_set_trnas_width(AES_CH_NUM, dmac_src_dst, dmac_trans_width_8);
    lalu_dmac_set_msize(AES_CH_NUM, dmac_src_dst, dmac_msize_4);
    
    return 0;
}

int lalu_aes_setkey_slot(int cipher_mode, unsigned int key_slot, unsigned int keybits)
{
    uint32_t config_temp;
    uint32_t slot_id = (uint32_t)key_slot;
    int ret = -1;
    
    config_temp = 0x0;
    
    switch(keybits) {
        case 128:
            config_temp &= ~(0x03 << 5);
            break;
        case 192:
            config_temp |= (0x01 << 5);
            config_temp &= ~(0x01 << 6);
            break;
        default:
            config_temp |= (0x01 << 6);
            config_temp &= ~(0x01 << 5);
            break;
    }

    if (cipher_mode == XTS_KEY_2) {
        slot_id |= KEY_CONFIG_SET_XTS_EN;
    }
    
    aes_core_map->ch_aes[AES_CH_NUM].config = config_temp;
    aes_config = aes_core_map->ch_aes[AES_CH_NUM].config;

    ret = load_key_to_engine(aes_key_mgt_map, slot_id);
    
    return ret;
}

#if defined (CONFIG_ENABLE_LALU_GCM)
static void lalu_gcm_mult(const unsigned char x[16], unsigned char output[16])
{
    lalu_set_aes_config(DMA_MODE, GMAC_MODE, 0);
    lalu_aes_dmac_operation(16, (uint32_t)x, (uint32_t)output, FIRST_BLK);
}

static void lalu_gcm_mask(mbedtls_gcm_context *ctx,
        const unsigned char *input,
        unsigned char *output)

{
    lalu_set_aes_config(DMA_MODE, GMAC_MODE, ctx->mode);
    aes_core_map->ch_aes[AES_CH_NUM].cipher_len = 0x80;
    lalu_aes_dmac_operation(16, (uint32_t)input, (uint32_t) output, FIRST_BLK);
}

int lalu_gcm_setkey(mbedtls_gcm_context *ctx,
                    mbedtls_cipher_id_t cipher,
                    const unsigned char *key,
                    unsigned int keybits)
{
    (void)ctx;
    (void)cipher;
    unsigned int key_slot = SHRAED_SW_KEY_SLOT0;

    memcpy(ctx->key, key, keybits/8);
    ctx->rk = key_slot;
    ctx->kb = keybits;
    
    return (0);
}

int lalu_gcm_starts(mbedtls_gcm_context *ctx, 
                    int mode, 
                    const unsigned char *iv, size_t iv_len)
{
    int errorCode = -1, i;
    uint32_t *iv_word = (uint32_t*)iv;
    uint32_t left = 0, totalBlocks = 0;
    uint8_t iv_left = iv_len % 16;
    unsigned char *iv_cat;
    size_t iv_len_temp;

    if (iv_len == 0 || iv_len >> 29 != 0) {
        return (MBEDTLS_ERR_GCM_BAD_INPUT);
    }

    ctx->mode = mode;
    ctx->len = 0;
    ctx->add_len = 0;
    ctx->out_addr = 0;
    ctx->rest_len = 0;
    ctx->aes_config = 0;
    
#if defined(CONFIG_LALU_CRYPTO_MIXED_MODE_ENABLE)
    memset(ctx->iv, 0, sizeof(ctx->iv));
#endif

    memset(ctx->buf, 0, sizeof(ctx->buf));

    memset((uint32_t*)aes_core_map->ch_aes[AES_CH_NUM].tag, 0, sizeof(aes_core_map->ch_aes[AES_CH_NUM].tag));

    lalu_key_mgr_program_key(aes_key_mgt_map, ctx->key, ctx->kb, SHRAED_SW_KEY_SLOT0);

    aes_core_map->ch_aes[AES_CH_NUM].cipher_len = 0;
    aes_core_map->ch_aes[AES_CH_NUM].gmac_len_0 = 0;
    aes_core_map->ch_aes[AES_CH_NUM].gmac_len_1 = 0;

    lalu_aes_setkey_slot(GCM_MODE, ctx->rk, ctx->kb);
    ctx->aes_config = aes_config;

    if (iv_len == 12) {
#if defined(CONFIG_LALU_CRYPTO_MIXED_MODE_ENABLE) 
        memcpy(ctx->iv, iv_word, 12);
        ctx->iv[3] = 0x01000000;
#else
        for (i = 0; i < 3; i++) {
            aes_core_map->ch_aes[AES_CH_NUM].iv[i] = iv_word[i];
        }
        aes_core_map->ch_aes[AES_CH_NUM].iv[3] = 0x01000000;
#endif
    } else {
        if (iv_len >= 16) {
            lalu_aes_dma_mode_operation(iv, iv_len, iv, GMAC_MODE, 0, FIRST_BLK, &left);
        }
        
        iv_len_temp = iv_len * 8;
        if (iv_left == 0) {
            iv_cat = mbedtls_calloc(16, sizeof(unsigned char));
            if (iv_cat == NULL) {
                return -1;
            }
            for (i = 16; i > 0; i--) {
                if (iv_len_temp > 0) {
                    *(iv_cat + i - 1) = iv_len_temp;
                    iv_len_temp = iv_len_temp >> 8;
                }
            }
            totalBlocks = 16;
        } else {
            iv_cat = mbedtls_calloc(32, sizeof(unsigned char));
            if (iv_cat == NULL) {
                return -1;
            }
            for (i = 32; i > 0; i--) {
                if (iv_len_temp > 0) {
                    *(iv_cat + i - 1) = iv_len_temp;
                    iv_len_temp = iv_len_temp >> 8;
                }
            }
            memcpy(iv_cat, (iv + (iv_len/16*16)), iv_left);
            totalBlocks = 32;
        }
        
        lalu_set_aes_config(DMA_MODE, GMAC_MODE, 0);
        lalu_aes_dmac_operation(totalBlocks, (uint32_t)iv_cat, (uint32_t)iv_cat, FIRST_BLK);
        
#if defined(CONFIG_LALU_CRYPTO_MIXED_MODE_ENABLE) 
        for (i = 0; i < 4; i++) {
            ctx->iv[i] = AES->TAG[i];
        }
#else
        memcpy((uint32_t*)aes_core_map->ch_aes[AES_CH_NUM].iv, (uint32_t*)aes_core_map->ch_aes[AES_CH_NUM].tag, sizeof(aes_core_map->ch_aes[AES_CH_NUM].iv));
#endif
        memset((uint32_t*)aes_core_map->ch_aes[AES_CH_NUM].tag, 0, sizeof(aes_core_map->ch_aes[AES_CH_NUM].tag));
        mbedtls_free(iv_cat);
    }

    return 0;
}

int lalu_gcm_update_ad(mbedtls_gcm_context *ctx, const unsigned char *add, size_t add_len)
{
    int errorCode = -1;
    const unsigned char *p;
    size_t use_len, offset;
    uint32_t left = 0;
    
    if (add_len>>29 !=0) {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }
    
#if defined(CONFIG_LALU_CRYPTO_MIXED_MODE_ENABLE) 
    lalu_key_mgr_program_key(ctx->key, ctx->kb, SHRAED_SW_KEY_SLOT0);
    load_key_to_engine(aes_key_mgt_map, ctx->rk);
#endif
    
    aes_config = ctx->aes_config;
    
    offset = ctx->add_len % 16;
    p = add;
    
    if (offset != 0) {
        use_len = 16 - offset;
        if (use_len < add_len) {
            use_len = add_len;
        }
        
        memcpy(ctx->buf + offset, p, use_len);
        if (offset + use_len == 16) {
            lalu_gcm_mult(ctx->buf, ctx->buf);
        }
        ctx->add_len += use_len;
        add_len -= use_len;
        p += use_len;
    }
    
    ctx->add_len += add_len;
    aes_core_map->ch_aes[AES_CH_NUM].gmac_len_0 = (ctx->add_len / 16) * 128;
    
    if (add_len >= 16) {
        lalu_aes_dma_mode_operation(p, add_len, p, GMAC_MODE, 0, FIRST_BLK, &left);
        add_len = add_len % 16;
    }
    
    if (add_len > 0) {
        memcpy(ctx->buf, (p + left), add_len);
    }
    
#if defined(CONFIG_LALU_CRYPTO_MIXED_MODE_ENABLE) 
    for (int i = 0; i < 4; i++) {
        *((uint32_t)ctx->base_ectr + i) = *(aes_core_map->ch_aes[AES_CH_NUM].tag + i);
    }
#endif
    
    return 0;
}

int lalu_gcm_update(mbedtls_gcm_context *ctx,
                    const unsigned char *input , size_t input_length,
                    unsigned char *output, size_t output_size,
                    size_t *output_length)
{
    int errorCode = -1;
    const unsigned char *p = input;
    unsigned char *out_p = (output - ctx->rest_len);
    size_t offset, input_length_remain;
    size_t use_len = 0;
    uint32_t left = 0;

    if (output_size < input_length) {
        return MBEDTLS_ERR_GCM_BUFFER_TOO_SMALL;
    }
    
#if defined(CONFIG_LALU_CRYPTO_MIXED_MODE_ENABLE)
    
#endif
    
    aes_config = ctx->aes_config;
    
    *output_length = (input_length + ctx->rest_len) / 16 * 16;
    
    if (input_length == 0) {
        return 0;
    }
    
    if (output > input && (size_t)(output - input) < input_length) {
        return -1;
    }
    
    if (ctx->len + input_length < ctx->len || (uint64_t) ctx->len + input_length > 0xfffffffe0ull)
        return -1;
    
    if (ctx->len == 0 && ctx->add_len % 16 != 0) {
        aes_core_map->ch_aes[AES_CH_NUM].gmac_len_0 = ctx->add_len * 8;
        lalu_gcm_mult(ctx->buf, ctx->buf);
    } else if (ctx->len == 0 && ctx->add_len == 0) {
        aes_core_map->ch_aes[AES_CH_NUM].cipher_len = 0;
        lalu_aes_slave_mode_operation(ECB_MODE, FIRST_BLK, AES_ENCRYPT);
        
        memcpy((uint32_t*)aes_core_map->ch_aes[AES_CH_NUM].ghash_key, (uint32_t*)aes_core_map->ch_aes[AES_CH_NUM].cpu_dataout, sizeof(aes_core_map->ch_aes[AES_CH_NUM].cpu_dataout));
    }
    
    offset = ctx->len % 16;
    if (offset != 0) {
        use_len = 16 - offset;
        if (use_len > input_length) {
            use_len = input_length;
        }
        
        memcpy(ctx->buf + offset, input, use_len);
        
        if (offset + use_len == 16) {
            lalu_gcm_mask(ctx, ctx->buf, out_p);
        }
        
        ctx->len += use_len;
        input_length -= use_len;
        p += use_len;
        if (offset + use_len == 16) {
            out_p += 16;
        }
    }
    
    aes_core_map->ch_aes[AES_CH_NUM].cipher_len = (ctx->len + input_length / 16) * 128;
    
    if (input_length >= 16) {
        lalu_aes_dma_mode_operation((input + use_len), input_length, out_p, GCM_MODE, ctx->mode, FIRST_BLK, &left);
        input_length_remain = input_length % 16;
    } else {
        input_length_remain = input_length;
    }
    
    ctx->len += input_length;
    ctx->rest_len = input_length_remain;
    
    if (input_length_remain > 0) {
        memcpy(ctx->buf, (p + left), input_length_remain);
        ctx->out_addr = (uint32_t)out_p + (int)(input_length / 16) * 16;
    }
    
#if defined(CONFIG_LALU_CRYPTO_MIXED_MODE_ENABLE)
    
#endif
    
    return 0;
}

int lalu_gcm_finish(mbedtls_gcm_context *ctx,
                    unsigned char *output, size_t output_size,
                    size_t *output_length,
                    unsigned char *tag, size_t tag_len)
{
    size_t offset;
    int aes_first, i;
    uint32_t *tag_word = (uint32_t*)tag;
    uint32_t iv;

    offset = ctx->len % 16;
    *output_length = offset;

#if defined(CONFIG_LALU_CRYPTO_MIXED_MODE_ENABLE)
    
#endif
    
    aes_config = ctx->aes_config;
    aes_core_map->ch_aes[AES_CH_NUM].gmac_len_0 = ctx->add_len * 8;
    
    if (ctx->len == 0 && ctx->add_len % 16 != 0) {
        lalu_gcm_mult(ctx->buf, ctx->buf);
    }
    
    if (tag_len > 16 || tag_len < 4)
        return -1;
    
    aes_core_map->ch_aes[AES_CH_NUM].cipher_len = ctx->len * 8;
    
    if (offset != 0) {
#if defined(CONFIG_LALU_CRYPTO_MIXED_MODE_ENABLE)
    
#endif
        lalu_set_aes_blk(AEAD_LAST_BLK);
        lalu_set_aes_config(DMA_MODE, GCM_MODE, ctx->mode);
        if (ctx->len < 16)
            aes_first = FIRST_BLK;
        else
            aes_first = CLEAR_FIRST_BLK;
        lalu_aes_dmac_operation(offset, (uint32_t)ctx->buf, (uint32_t)ctx->out_addr, aes_first);
    
    } else {
        if (ctx->len != 0) {
#if defined(CONFIG_LALU_CRYPTO_MIXED_MODE_ENABLE)
#else
            iv = (((aes_core_map->ch_aes[AES_CH_NUM].iv[3] & 0x000000ff) << 24) | 
                    ((aes_core_map->ch_aes[AES_CH_NUM].iv[3] & 0x0000ff00) << 8) | 
                    ((aes_core_map->ch_aes[AES_CH_NUM].iv[3] & 0x00ff0000) >> 8) | 
                    ((aes_core_map->ch_aes[AES_CH_NUM].iv[3] & 0xff000000) >> 24));
            
            iv = iv - (ctx->len / 16 + 1);
            
            aes_core_map->ch_aes[AES_CH_NUM].iv[3] = (((iv & 0x000000ff) << 24) | 
                    ((iv & 0x0000ff00) << 8) | 
                    ((iv & 0x00ff0000) >> 8) | 
                    ((iv & 0xff000000) >> 24));
            
            iv = (((aes_core_map->ch_aes[AES_CH_NUM].iv[2] & 0x000000ff) << 24) | 
                    ((aes_core_map->ch_aes[AES_CH_NUM].iv[2] & 0x0000ff00) << 8) | 
                    ((aes_core_map->ch_aes[AES_CH_NUM].iv[2] & 0x00ff0000) >> 8) | 
                    ((aes_core_map->ch_aes[AES_CH_NUM].iv[2] & 0xff000000) >> 24));
            iv = iv - ((ctx->len + 1 ) >> 32);
            
            aes_core_map->ch_aes[AES_CH_NUM].iv[2] = (((iv & 0x000000ff) << 24) | 
                    ((iv & 0x0000ff00) << 8) | 
                    ((iv & 0x00ff0000) >> 8) | 
                    ((iv & 0xff000000) >> 24));
#endif
        }
        lalu_aes_slave_mode_operation(GCM_MODE, AEAD_LAST_BLK, ctx->mode);
    }
    
    if (output != NULL && output_size != 0) {
        memcpy(output, (unsigned int*)ctx->out_addr, *output_length);
    }
    
    for (i = 0; i < 4; i++) {
        tag_word[i] = aes_core_map->ch_aes[AES_CH_NUM].tag[i];
    }
    
    aes_core_map->ch_aes[AES_CH_NUM].config &= ~(0x01 << 16);
    
    return 0;
}

#endif  /* CONFIG_ENABLE_LALU_GCM */

#endif  /* CONFIG_ENABLE_LALU_AES */
