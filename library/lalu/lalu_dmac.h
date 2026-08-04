#ifndef __LALU_DMAC_H__
#define __LALU_DMAC_H__

#include <stdint.h>

#define LALU_BIT_MASK_WIDTH(__bfws, __bits) ((uint32_t)((__bfws) == 32) ? \
    0xFFFFFFFF : (((1 << (__bits)) - 1) << (__bfws)))

#define LALU_BITS_SET_VAL(__datum, __bfws, __val, bit_num)  \
    ((__datum) = ((uint32_t)(__datum) &~LALU_BIT_MASK_WIDTH(__bfws, bit_num)) | \
    ((__val << (__bfws)) & LALU_BIT_MASK_WIDTH(__bfws, bit_num)))

#define LALU_BITS_TO_BYTES(bits)    (((bits) + 7u) / 8u)
#define LALU_BYTES_TO_BITS(bypte)   ((bytes) * 8u)

#define BIT(n)              (1 << n)

#define CH_CTRL_MASK        0xFFFF0000
#define INT_EN              (0x01 << 0)
#define DST_TR_WIDTH(n)     (n << 1)
#define SRC_TR_WIDTH(n)     (n << 4)
#define DST_MSIZE(n)        (n << 11)
#define SRC_MSIZE(n)        (n << 14)

#define STATUS_INT_MASK     0x1F
#define STATUS_INT_ERR      (0x01 << 4)
#define STATUS_INT_DSTT     (0x01 << 3)
#define STATUS_INT_SRCT     (0x01 << 2)
#define STATUS_INT_BLOCK    (0x01 << 1)
#define STATUS_INT_TFR      (0x01 << 0)

#define TFR_INT_MASK        0xFFFF0000
#define CH_INT_MASK(n)      (0x01 << n)
#define CH_INT_MASK_WE(n)   (1 << (n + 8))
#define CH_CLR_TFR(n)       (0x01 << n)

#define BIT_OFF_DMAC_CTL_L_INT_EN           ((uint32_t) 0)
#define BIT_WID_DMAC_CTL_L_INT_EN           ((uint32_t) 1)
#define BIT_OFF_DMAC_CTL_L_SRC_MSIZE        ((uint32_t) 14)
#define BIT_WID_DMAC_CTL_L_SRC_MSIZE        ((uint32_t) 3)
#define BIT_OFF_DMAC_CTL_L_DEST_MSIZE       ((uint32_t) 11)
#define BIT_WID_DMAC_CTL_L_DEST_MSIZE       ((uint32_t) 3)
#define BIT_OFF_DMAC_CTL_L_DST_TR_WIDTH     ((uint32_t) 1)
#define BIT_WID_DMAC_CTL_L_DST_TR_WIDTH     ((uint32_t) 3)
#define BIT_OFF_DMAC_CTL_L_SRC_TR_WIDTH     ((uint32_t) 4)
#define BIT_WID_DMAC_CTL_L_SRC_TR_WIDTH     ((uint32_t) 3)
#define BIT_OFF_DMAC_CFG_H_FIFO_MODE        ((uint32_t) 1)
#define BIT_WID_DAMC_CFG_H_FIFO_MODE        ((uint32_t) 1)

enum {
    ECB_MODE = 0x0,
    CBC_MODE = 0x1,
    CFB_MODE = 0x2,
    OFB_MODE = 0x3,
    CTR_MODE = 0x4,
    GMAC_MODE = 0x5,
    GCM_MODE = 0x6,
    CMAC_MODE = 0x7,
    XTS_MODE = 0x8,
    CBC_MAC_MODE = 0x9,
    CCM_MODE = 0xa,
};

enum lalu_dmac_key_size {
    key_128 = 0x00,
    key_192 = 0x01,
    key_256 = 0x10,
};

enum lalu_dmac_irq_type {
    dmac_irq_none = 0x00,
    dmac_irq_tfr = 0x01,
    dmac_irq_block = 0x02,
    dmac_irq_srctran = 0x04,
    dmac_irq_dsttran = 0x08,
    dmac_irq_err = 0x10,
    dmac_irq_all = 0x1f
};

enum lalu_dmac_src_dst_sel {
    dmac_src = 0x01,
    dmac_dst = 0x02,
    dmac_src_dst = 0x03,
};

enum lalu_trans_width {
    dmac_trans_width_8 = 0x0,
    dmac_trans_width_16 = 0x01,
    dmac_trans_width_32 = 0x02,
    dmac_trans_width_64 = 0x03,
    dmac_trans_width_128 = 0x04,
    dmac_trans_width_256 = 0x05
};

enum lalu_dmac_fifo_mode {
    dmac_fifo_mode_single = 0x0,
    dmac_fifo_mode_falf = 0x01
};

enum lalu_dmac_msize {
    dmac_msize_1 = 0x0,
    dmac_msize_4 = 0x01,
    dmac_msize_8 = 0x02,
    dmac_msize_16 = 0x03,
    dmac_msize_32 = 0x04,
    dmac_msize_64 = 0x05,
    dmac_msize_128 = 0x06,
    dmac_msize_256 = 0x07,
};

struct lalu_dmac_regs {
    struct {
        volatile uint32_t sar_l;
        volatile uint32_t sar_h;
        volatile uint32_t dar_l;
        volatile uint32_t dar_h;
        volatile uint32_t llp_l;
        volatile uint32_t llp_h;
        volatile uint32_t ctl_l;
        volatile uint32_t ctl_h;
        volatile uint32_t sstat_l;
        volatile uint32_t sstat_h;
        volatile uint32_t dstat_l;
        volatile uint32_t dstat_h;
        volatile uint32_t sstatar_l;
        volatile uint32_t sstatar_h;
        volatile uint32_t dstatar_l;
        volatile uint32_t dstatar_h;
        volatile uint32_t cfg_l;
        volatile uint32_t cfg_h;
        volatile uint32_t sgr_l;
        volatile uint32_t sgr_h;
        volatile uint32_t dsr_l;
        volatile uint32_t dsr_h;
    } ch[8];
    
    volatile uint32_t raw_tfr_l;
    volatile uint32_t raw_tfr_h;
    volatile uint32_t raw_block_l;
    volatile uint32_t raw_block_h;
    volatile uint32_t raw_srctran_l;
    volatile uint32_t raw_srctran_h;
    volatile uint32_t raw_dsttran_l;
    volatile uint32_t raw_dsttran_h;
    volatile uint32_t raw_err_l;
    volatile uint32_t raw_err_h;
    
    volatile uint32_t status_tfr_l;
    volatile uint32_t status_tfr_h;
    volatile uint32_t status_block_l;
    volatile uint32_t status_block_h;
    volatile uint32_t status_srctran_l;
    volatile uint32_t status_srctran_h;
    volatile uint32_t status_dsttran_l;
    volatile uint32_t status_dsttran_h;
    volatile uint32_t status_err_l;
    volatile uint32_t status_err_h;
    
    volatile uint32_t mask_tfr_l;
    volatile uint32_t mask_tfr_h;
    volatile uint32_t mask_block_l;
    volatile uint32_t mask_block_h;
    volatile uint32_t mask_srctran_l;
    volatile uint32_t mask_srctran_h;
    volatile uint32_t mask_dsttran_l;
    volatile uint32_t mask_dsttran_h;
    volatile uint32_t mask_err_l;
    volatile uint32_t mask_err_h;
        
    volatile uint32_t clear_tfr_l;
    volatile uint32_t clear_tfr_h;
    volatile uint32_t clear_block_l;
    volatile uint32_t clear_block_h;
    volatile uint32_t clear_srctran_l;
    volatile uint32_t clear_srctran_h;
    volatile uint32_t clear_dsttran_l;
    volatile uint32_t clear_dsttran_h;
    volatile uint32_t clear_err_l;
    volatile uint32_t clear_err_h;
    volatile uint32_t status_int_l;
    volatile uint32_t status_int_h;
    
    volatile uint32_t reg_src_reg_l;
    volatile uint32_t reg_src_reg_h;
    volatile uint32_t reg_dst_reg_l;
    volatile uint32_t reg_dst_reg_h;
    volatile uint32_t sgl_rq_src_reg_l;
    volatile uint32_t sgl_rq_src_reg_h;
    volatile uint32_t sgl_rq_dst_reg_l;
    volatile uint32_t slg_rq_dst_reg_h;
    volatile uint32_t lst_src_reg_l;
    volatile uint32_t lst_src_reg_h;
    volatile uint32_t lst_dst_reg_l;
    volatile uint32_t lst_dst_reg_h;
    
    volatile uint32_t dma_cfg_reg_l;
    volatile uint32_t dma_cfg_reg_h;
    volatile uint32_t ch_en_reg_l;
    volatile uint32_t ch_en_reg_h;
    volatile uint32_t dma_id_reg_l;
    volatile uint32_t dma_id_reg_h;
    volatile uint32_t dma_test_reg_l;
    volatile uint32_t dma_test_reg_h;
    volatile uint32_t old_version_id_l;
    volatile uint32_t old_version_id_h;
    volatile uint32_t reserved_low;
    volatile uint32_t reserved_high;
    volatile uint32_t dmac_comp_params_6_l;
    volatile uint32_t dmac_comp_params_6_h;
        
};

int lalu_crypto_dma_init(void *base_address, uint8_t ch_num);
int lalu_dmac_enable_channel(uint8_t ch_num);
void lalu_dmac_enable_irq(uint8_t ch_num);
int lalu_dmac_unmask_irq(uint8_t ch_num, enum lalu_dmac_irq_type ch_irq);
void lalu_dmac_set_msize(uint8_t ch_num, enum lalu_dmac_src_dst_sel sd_sel,
    enum lalu_dmac_msize xf_length);
void lalu_dmac_set_trnas_width(uint8_t ch_num, enum lalu_dmac_src_dst_sel sd_sel,
    enum lalu_trans_width xf_length);
void lalu_dmac_set_prot_sec_mode(uint8_t ch_num);
void lalu_dmac_set_fifo_mode(uint8_t ch_num, enum lalu_dmac_fifo_mode fifo_mode);
void lalu_dmac_set_ts(uint8_t ch_num, uint32_t input, uint32_t output, uint32_t block_ts);
int lalu_dmac_init_config_reg(uint8_t ch_num);
void lalu_dmac_clear_tfr(uint8_t ch_num);
void lalu_dmac_wait_done(uint8_t ch_num);

#endif  /* __LALU_DMAC_H__ */
