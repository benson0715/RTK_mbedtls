#include <stdio.h>
#include "lalu_dmac.h"

volatile struct lalu_dmac_regs *dmac_map;

static void lalu_dmac_claer_all_channel_irqs(void)
{
#if 0
    *(uint32_t*)(AESDMA_BASE + 0x338ul) = 0x00fffful;   // clear_tfr_l
    *(uint32_t*)(AESDMA_BASE + 0x340ul) = 0x00fffful;   // clear_block_l
    *(uint32_t*)(AESDMA_BASE + 0x348ul) = 0x00fffful;   // clear_srctran_l
    *(uint32_t*)(AESDMA_BASE + 0x350ul) = 0x00fffful;   // clear_dsttran_l
    *(uint32_t*)(AESDMA_BASE + 0x358ul) = 0x00fffful;   // clear_err_l
#endif
    dmac_map->clear_tfr_l = 0x00ffff;
    dmac_map->clear_block_l = 0x00ffff;
    dmac_map->clear_srctran_l = 0x00ffff;
    dmac_map->clear_dsttran_l = 0x00ffff;
    dmac_map->clear_err_l = 0x00ffff;
}

static int lalu_damc_initialize(void)
{
    dmac_map->ch_en_reg_l = 0x01;
    dmac_map->ch_en_reg_l = 0xff00ff00;
    lalu_dmac_claer_all_channel_irqs();
    
    if ((dmac_map->ch_en_reg_l != 0) ||   // ch_en_reg_l
        (dmac_map->status_tfr_l != 0) ||   // status_tfr_l
        (dmac_map->status_block_l != 0) ||   // status_block_l
        (dmac_map->status_srctran_l != 0) ||   // status_srctran_l
        (dmac_map->status_dsttran_l != 0) ||   // status_dsttran_l
        (dmac_map->clear_err_l != 0)) {   // status_err_l
        
        return -1;
    } 
        
    return 0;
#if 0    
    *(uint32_t*)(AESDMA_BASE + 0x398ul) = 0x01ul;       // cfg_reg_l
    *(uint32_t*)(AESDMA_BASE + 0x3a0ul) = 0xff00ff00;   // ch_en_reg_l
    
    lalu_dmac_claer_all_channel_irqs();
    
    if ((*(uint32_t*)(AESDMA_BASE + 0x3a0ul) != 0) ||   // ch_en_reg_l
        (*(uint32_t*)(AESDMA_BASE + 0x2e8ul) != 0) ||   // status_tfr_l
        (*(uint32_t*)(AESDMA_BASE + 0x2f0ul) != 0) ||   // status_block_l
        (*(uint32_t*)(AESDMA_BASE + 0x2f8ul) != 0) ||   // status_srctran_l
        (*(uint32_t*)(AESDMA_BASE + 0x300ul) != 0) ||   // status_dsttran_l
        (*(uint32_t*)(AESDMA_BASE + 0x308ul) != 0)) {   // status_err_l
        
        return -1;
    } 
        
    return 0;
#endif
}

int lalu_crypto_dma_init(void *base_address, uint8_t ch_num)
{
    int ret;
    
    dmac_map = base_address;
    
    lalu_damc_initialize();
    lalu_dmac_enable_irq(ch_num);
    lalu_dmac_unmask_irq(ch_num, dmac_irq_tfr);
    lalu_dmac_init_config_reg(ch_num);
    
    return 0;
}

int lalu_dmac_enable_channel(uint8_t ch_num)
{
    dmac_map->dma_cfg_reg_l = 0x01;
    dmac_map->ch_en_reg_l = 0xffffffff;
    
    return 0;
}

void lalu_dmac_enable_irq(uint8_t ch_num)
{
    LALU_BITS_SET_VAL(dmac_map->ch[ch_num].ctl_l, 
        BIT_OFF_DMAC_CTL_L_INT_EN, 1, 
        BIT_WID_DMAC_CTL_L_INT_EN);
}

int lalu_dmac_unmask_irq(uint8_t ch_num, enum lalu_dmac_irq_type ch_irq)
{
    uint32_t dmac_ch_num = CH_INT_MASK(ch_num) | CH_INT_MASK_WE(ch_num);

    switch(ch_irq) {
        case dmac_irq_tfr:
            dmac_map->mask_tfr_l = dmac_ch_num;
            break;
        case dmac_irq_block:
            dmac_map->mask_block_l = dmac_ch_num;
            break;
        case dmac_irq_srctran:
            dmac_map->mask_srctran_l = dmac_ch_num;
            break;
        case dmac_irq_dsttran:
            dmac_map->mask_dsttran_l = dmac_ch_num;
            break;
        case dmac_irq_err:
            dmac_map->mask_err_l = dmac_ch_num;
            break;
        case dmac_irq_all:
            dmac_map->mask_tfr_l = dmac_ch_num;
            dmac_map->mask_block_l = dmac_ch_num;
            dmac_map->mask_srctran_l = dmac_ch_num;
            dmac_map->mask_dsttran_l = dmac_ch_num;
            dmac_map->mask_err_l = dmac_ch_num;
            break;
        default:
            return -1;
    }
    
    return 0;
}

void lalu_dmac_set_msize(uint8_t ch_num, enum lalu_dmac_src_dst_sel sd_sel,
    enum lalu_dmac_msize xf_length)
{
    if ((sd_sel == dmac_src) || (sd_sel == dmac_src_dst)) {
        LALU_BITS_SET_VAL(dmac_map->ch[ch_num].ctl_l, 
            BIT_OFF_DMAC_CTL_L_SRC_MSIZE, xf_length, 
            BIT_WID_DMAC_CTL_L_SRC_MSIZE);
    }
    
    if ((sd_sel == dmac_dst) || (sd_sel == dmac_src_dst)) {
        LALU_BITS_SET_VAL(dmac_map->ch[ch_num].ctl_l, 
            BIT_OFF_DMAC_CTL_L_DEST_MSIZE, xf_length, 
            BIT_WID_DMAC_CTL_L_DEST_MSIZE);
    }
}

void lalu_dmac_set_trnas_width(uint8_t ch_num, enum lalu_dmac_src_dst_sel sd_sel,
    enum lalu_trans_width xf_length)
{
    if ((sd_sel == dmac_src) || (sd_sel == dmac_src_dst)) {
        LALU_BITS_SET_VAL(dmac_map->ch[ch_num].ctl_l, 
            BIT_OFF_DMAC_CTL_L_SRC_TR_WIDTH, xf_length, 
            BIT_WID_DMAC_CTL_L_SRC_TR_WIDTH);
    }
    
    if ((sd_sel == dmac_dst) || (sd_sel == dmac_src_dst)) {
        LALU_BITS_SET_VAL(dmac_map->ch[ch_num].ctl_l, 
            BIT_OFF_DMAC_CTL_L_DST_TR_WIDTH, xf_length, 
            BIT_WID_DMAC_CTL_L_DST_TR_WIDTH);
    }
}

void lalu_dmac_set_prot_sec_mode(uint8_t ch_num)
{
    dmac_map->ch[ch_num].cfg_h &= ~(0x01ul << 3);
}

void lalu_dmac_set_fifo_mode(uint8_t ch_num, enum lalu_dmac_fifo_mode fifo_mode)
{
    LALU_BITS_SET_VAL(dmac_map->ch[ch_num].cfg_h, 
        BIT_OFF_DMAC_CFG_H_FIFO_MODE, fifo_mode, 
        BIT_WID_DAMC_CFG_H_FIFO_MODE);
}
    
void lalu_dmac_set_ts(uint8_t ch_num, uint32_t input, uint32_t output, uint32_t block_ts)
{
    dmac_map->ch[ch_num].sar_l = input;
    dmac_map->ch[ch_num].dar_l = output;
    dmac_map->ch[ch_num].ctl_h = block_ts;
}

int lalu_dmac_init_config_reg(uint8_t ch_num)
{
    lalu_dmac_set_fifo_mode(ch_num, dmac_fifo_mode_falf);
    lalu_dmac_set_prot_sec_mode(ch_num);

    return 0;
}

void lalu_dmac_clear_tfr(uint8_t ch_num)
{
    dmac_map->clear_tfr_l = CH_CLR_TFR(ch_num);
}

void lalu_dmac_wait_done(uint8_t ch_num)
{
    uint32_t done_value = CH_CLR_TFR(ch_num);

    while(1) {
        if (dmac_map->status_tfr_l & done_value) {
            break;
        }
    }

    dmac_map->clear_tfr_l = done_value;
    dmac_map->clear_block_l = done_value;
}
