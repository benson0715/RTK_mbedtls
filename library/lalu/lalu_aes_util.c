#if defined (CONFIG_ENABLE_LALU_AES)
#include <stdio.h>
#include "lalu_aes.h"
#include <string.h>

extern uint32_t aes_config;
extern volatile struct lalu_dmac_regs *dmac_map;
extern volatile struct lalu_aes_core_regs *aes_core_map;
extern volatile struct lalu_aes_int_and_constant_regs *dmac_aes_int_map;

int lalu_set_aes_blk(int aes_config_blk)
{
    uint32_t config_temp = aes_config;
    
    switch(aes_config_blk) {
    case FIRST_BLK:
        config_temp |= AES_CONFIG_FIRST_BLK;
        break;
    case AEAD_LAST_BLK:
        config_temp |= AES_CONFIG_AEAD_LAST_BLK;
        break;
    case MAC_LAST_BLK:
        config_temp |= AES_CONFIG_MAC_LAST_BLK;
        break;
    case CLEAR_FIRST_BLK:
        config_temp &= ~AES_CONFIG_FIRST_BLK;
        break;
    case CLEAR_AEAD_LAST_BLK:
        config_temp &= ~AES_CONFIG_AEAD_LAST_BLK;
        break;
    case CLEAR_MAC_LAST_BLK:
        config_temp &= ~AES_CONFIG_MAC_LAST_BLK;
        break;
    }
    
    aes_config = config_temp;
    aes_core_map->ch_aes[AES_CH_NUM].config = config_temp;
    
    return 0;
}

void lalu_set_aes_config(int dma_mode, int cipher_mode, int encrypt)
{
    uint32_t config_temp = aes_config;
    
    config_temp &= AES_CONFIG_MASK;
    if (dma_mode) {
        config_temp |= AES_CONFIG_DMA_MODE;
    }
    
    config_temp |= (cipher_mode << 1);
    
    if(encrypt) {
        config_temp |= AES_CONFIG_ENCRYPT;
    }
    
    if (cipher_mode == ECB_MODE || cipher_mode == CBC_MODE || cipher_mode == XTS_MODE) {
        config_temp |= AES_CONFIG_DE_KEY_GEN;
    }
    
    aes_config = config_temp;
    aes_core_map->ch_aes[AES_CH_NUM].config = config_temp;
}

int lalu_aes_dmac_operation(uint32_t block_ts, uint32_t input, uint32_t output, int aes_config_blk)
{
    unsigned int errorCode;
    
    lalu_dmac_set_ts(AES_CH_NUM, input, output, block_ts);
    lalu_set_aes_blk(aes_config_blk);
    lalu_dmac_enable_channel(AES_CH_NUM);

    while(!(dmac_map->status_tfr_l & 0x1));
    dmac_map->clear_tfr_l = 0x01;
    dmac_map->clear_block_l = 0x01;

    aes_config = aes_core_map->ch_aes[AES_CH_NUM].config;

    return 0;
}

int lalu_aes_slave_mode_operation(int cipher_mode, int set_last, int encrypt)
{
    lalu_set_aes_config(SLAVE_MODE, cipher_mode, encrypt);
    
    if (set_last) {
        lalu_set_aes_blk(set_last);
    }
    
    if (set_last == FIRST_BLK) {
        memset((uint32_t*)aes_core_map->ch_aes[AES_CH_NUM].cpu_datain, 0x0, sizeof(aes_core_map->ch_aes[AES_CH_NUM].cpu_datain));
    }
    
    if (set_last == MAC_LAST_BLK) {
        aes_core_map->ch_aes[AES_CH_NUM].cpu_datain[3] = 0x0;
        aes_core_map->ch_aes[AES_CH_NUM].cpu_datain[2] = 0x0;
        aes_core_map->ch_aes[AES_CH_NUM].cpu_datain[1] = 0x0;
        aes_core_map->ch_aes[AES_CH_NUM].cpu_datain[0] = 0x80;
    }
        
    while(!(dmac_aes_int_map->aes_int_chn & 0x1));
    dmac_aes_int_map->ch_aes[AES_CH_NUM].clear_aes = 0x1;
    
    return 0;
}

int lalu_aes_dma_mode_operation(const unsigned char *input, 
                                size_t input_length,
                                const unsigned char *output,
                                int cipher_mode,
                                int encrypt,
                                int aes_config_blk,
                                uint32_t *left)
{
    uint32_t blockSize, numBlocks, totalBlocks, totalBlockSize, address_offset;
    uint32_t input_temp, output_temp;
    
    *left = 0;
    
    if (cipher_mode == GCM_MODE || cipher_mode == CMAC_MODE || cipher_mode == GMAC_MODE) {
        totalBlockSize = (int)(input_length / 16) * 16;
    } else {
        totalBlockSize = (int)input_length;
    }
    
    numBlocks = (totalBlockSize + DMA_AES_MAX_BLOCK_SIZE - 1) / DMA_AES_MAX_BLOCK_SIZE;
    totalBlocks = numBlocks;
    
    lalu_set_aes_config(DMA_MODE, cipher_mode, encrypt);

    while(numBlocks > 0) {
        if (numBlocks > 1) {
            blockSize = DMA_AES_MAX_BLOCK_SIZE;
            aes_core_map->ch_aes[AES_CH_NUM].cipher_len = 8 * DMA_AES_MAX_BLOCK_SIZE;
        } else if (totalBlockSize % DMA_AES_MAX_BLOCK_SIZE == 0) {
            blockSize = DMA_AES_MAX_BLOCK_SIZE;
        } else {
            blockSize = totalBlockSize % DMA_AES_MAX_BLOCK_SIZE;
        }
        
        address_offset = (totalBlocks - numBlocks) * DMA_AES_MAX_BLOCK_SIZE;
        input_temp = (uint32_t) input + address_offset;
        output_temp = (uint32_t) output + address_offset;
        
        lalu_aes_dmac_operation(blockSize, input_temp, output_temp, aes_config_blk);
        
        numBlocks -= 1;
        *left += blockSize;
    }
    
    return 0;
}

#endif  /* CONFIG_ENABLE_LALU_AES */
