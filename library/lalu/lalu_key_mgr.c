#include <string.h>
#include "lalu_key_mgr.h"

#define read_word(addr)         *(uint32_t*)(addr)
#define write_word(addr, val)   *(uint32_t*)(addr) = val

#define KEYGMGR_BASE                0x40046000ul
#define KEYGMGR_KEY_SEL_NUM         (KEYGMGR_BASE + 0x00ul)
#define KEYGMGR_KEY_SETUP_TRIG      (KEYGMGR_BASE + 0x04ul)
#define KEYGMGR_SW_KEY_7            (KEYGMGR_BASE + 0x10ul)
#define KEYGMGR_SW_KEY_6            (KEYGMGR_BASE + 0x14ul)
#define KEYGMGR_SW_KEY_5            (KEYGMGR_BASE + 0x18ul)
#define KEYGMGR_SW_KEY_4            (KEYGMGR_BASE + 0x1cul)
#define KEYGMGR_SW_KEY_3            (KEYGMGR_BASE + 0x20ul)
#define KEYGMGR_SW_KEY_2            (KEYGMGR_BASE + 0x24ul)
#define KEYGMGR_SW_KEY_1            (KEYGMGR_BASE + 0x28ul)
#define KEYGMGR_SW_KEY_0            (KEYGMGR_BASE + 0x2cul)
#define KEYGMGR_S_KEY0_7            (KEYGMGR_BASE + 0x30ul)
#define KEYGMGR_S_KEY0_6            (KEYGMGR_BASE + 0x34ul)
#define KEYGMGR_S_KEY0_5            (KEYGMGR_BASE + 0x38ul)
#define KEYGMGR_S_KEY0_4            (KEYGMGR_BASE + 0x3cul)
#define KEYGMGR_S_KEY0_3            (KEYGMGR_BASE + 0x40ul)
#define KEYGMGR_S_KEY0_2            (KEYGMGR_BASE + 0x44ul)
#define KEYGMGR_S_KEY0_1            (KEYGMGR_BASE + 0x48ul)
#define KEYGMGR_S_KEY0_0            (KEYGMGR_BASE + 0x4cul)

int32_t lalu_key_mgr_read_key(unsigned char *key, unsigned int keybits,
    unsigned int slot_id)
{
#if 0
    int i;
    uint32_t *key_word = (uint32_t*)key;
    
    if (slot_id > KEY_MGT_SLOT_MAX || slot_id < SHRAED_SW_KEY_SLOT0) {
        return -1;
    }
    
    if (keybits > KEY_MGT_MAX_BITS) {
        return -1;
    }
    
    int offset = (
        (keybits == 256) ? 0 :
        (keybits == 192) ? 2 :
        4
    );
    int idx = 8 - offset;
    
    switch (slot_id) {
    
    }
#endif 
    return 0;
}      
        
int32_t lalu_key_mgr_program_key(volatile struct lalu_key_manager_regs *key_mgt_map, const unsigned char *key, unsigned int keybits, unsigned int slot_id)
{
    int i;
    uint32_t *key_word = (uint32_t*)key;
    int offset = (
        (keybits == 256) ? 0 :
        (keybits == 192) ? 2 :
        4
    );
    
    int idx = 8 - offset;
    
    switch(slot_id) {
        case SHRAED_SW_KEY_SLOT0:
            for (i = 0; i < idx; i++) {
                key_mgt_map->shared_key_0[i + offset] = key_word[i];
            }
            break;
        case SHRAED_SW_KEY_SLOT1:
            for (i = 0; i < idx; i++) {
                key_mgt_map->shared_key_1[i + offset] = key_word[i];
            }
            break;
        case SHRAED_SW_KEY_SLOT2:
            for (i = 0; i < idx; i++) {
                key_mgt_map->shared_key_2[i + offset] = key_word[i];
            }
            break;
        case SHRAED_SW_KEY_SLOT3:
            for (i = 0; i < idx; i++) {
                key_mgt_map->shared_key_3[i + offset] = key_word[i];
            }
            break;
        case PSM_KEY_SLOT0:
            for (i = 0; i < idx; i++) {
                key_mgt_map->secure_key_0[i + offset] = key_word[i];
            }
            break;
    }
    
    return 0;
}

int load_key_to_engine(volatile struct lalu_key_manager_regs *key_mgt_map, uint32_t slot_id)
{
    key_mgt_map->key_config = slot_id;
    key_mgt_map->key_setup_trigger = 0x01;
    while(!(key_mgt_map->key_setup_trigger & 0x1));
    return (key_mgt_map->key_setup_trigger & KEY_SETUP_TRIGGER_ERROR);
}
