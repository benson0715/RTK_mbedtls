#ifndef __LALU_KEY_MGR_H__
#define __LALU_KEY_MGR_H__

#include "lalu_dmac.h"

#define KEY_MGT_MAX_BITS    256
#define SW_KEY_SLOT_MIN     32
#define KEY_CONFIG_SET_XTS_EN  BIT(8)
#define KEY_SETUP_TRIGGER_ERROR BIT(31)

enum lalu_key_mgt_slot_enum {
    SHRAED_HW_KEY_SLOT0 = 0,
    SHRAED_HW_KEY_SLOT1 = 1,
    SECURE_HW_KEY_SLOT0 = 2,
    SECURE_HW_KEY_SLOT1 = 3,
    SHRAED_SW_KEY_SLOT0 = 33,
    SHRAED_SW_KEY_SLOT1 = 34,
    SHRAED_SW_KEY_SLOT2 = 35,
    SHRAED_SW_KEY_SLOT3 = 36,
    PSM_KEY_SLOT0 = 37,
    KEY_MGT_SLOT_MAX = PSM_KEY_SLOT0,
};

struct lalu_key_manager_regs {
    volatile uint32_t key_config;
    volatile uint32_t key_setup_trigger;
    volatile uint32_t reserved_0[2];
    volatile uint32_t shared_key_0[8];
    volatile uint32_t shared_key_1[8];
    volatile uint32_t shared_key_2[8];
    volatile uint32_t shared_key_3[8];
    volatile uint32_t secure_key_0[8];
};

int32_t lalu_key_mgr_program_key(volatile struct lalu_key_manager_regs *key_mgt_map, const unsigned char *key, unsigned int keybits, unsigned int slot_id);
int load_key_to_engine(volatile struct lalu_key_manager_regs *key_mgt_map, uint32_t slot_id);

#endif  /* __LALU_KEY_MGR_H__ */
