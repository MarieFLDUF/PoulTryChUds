# PoulTryChUds


```

#include "board_auth.h"
#include "cmox_crypto.h"
#include <stdbool.h>
#include <string.h>

#define KEY_ADDR   0x080C0000u          /* secteur 7 : retiré de FLASH dans le linker script */
#define KEY_MAGIC  0x4B455932u
#define CURVE      CMOX_ECC_ED25519_OPT_LOWMEM
#define MATH       CMOX_MATH_FUNCS_SMALL   /* selon la version : CMOX_ECC256_MATH_FUNCS */

typedef struct {
    uint32_t magic;
    uint32_t priv_len;
    uint8_t  priv[64];                  /* format cmox : secret(32) || clé publique(32) */
    uint8_t  pub[32];
} auth_key_t;

#define KEY  ((const auth_key_t *)KEY_ADDR)

static uint8_t    work[4096];           /* tampon CryptoLib (CMOX_ECC_ERR_MEMORY_FAIL si trop petit) */
static auth_key_t k;                    /* hors pile : la pile d'une tâche FreeRTOS déborde vite */

/* RFC 8032, test 2 : si la CryptoLib ne redonne pas exactement cette signature,
 * elle est mal initialisée (CRC) et le PC refusera tout ce qu'elle signe. */
static const uint8_t kat_priv[64] = {
    0x4c,0xcd,0x08,0x9b,0x28,0xff,0x96,0xda,0x9d,0xb6,0xc3,0x46,0xec,0x11,0x4e,0x0f,
    0x5b,0x8a,0x31,0x9f,0x35,0xab,0xa6,0x24,0xda,0x8c,0xf6,0xed,0x4f,0xb8,0xa6,0xfb,
    0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc,
    0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c,
};
static const uint8_t kat_msg[1] = { 0x72 };
static const uint8_t kat_sig[64] = {
    0x92,0xa0,0x09,0xa9,0xf0,0xd4,0xca,0xb8,0x72,0x0e,0x82,0x0b,0x5f,0x64,0x25,0x40,
    0xa2,0xb2,0x7b,0x54,0x16,0x50,0x3f,0x8f,0xb3,0x76,0x22,0x23,0xeb,0xdb,0x69,0xda,
    0x08,0x5a,0xc1,0xe4,0x3e,0x15,0x99,0x6e,0x45,0x8f,0x36,0x13,0xd0,0xf1,0x1d,0x8c,
    0x38,0x7b,0x2e,0xae,0xb4,0x30,0x2a,0xee,0xb0,0x0d,0x29,0x16,0x12,0xbb,0x0c,0x00,
};

static void flash_sync(void)
{
    SCB_InvalidateDCache_by_Addr((uint32_t *)KEY_ADDR, sizeof(auth_key_t));
}

static bool sign(const uint8_t *priv, const uint8_t *msg, size_t len, uint8_t sig[64])
{
    cmox_ecc_handle_t h;
    size_t sig_len = 0;

    cmox_ecc_construct(&h, MATH, work, sizeof work);
    cmox_ecc_retval_t r = cmox_eddsa_sign(&h, CURVE, priv, 64, msg, len, sig, &sig_len);
    cmox_ecc_cleanup(&h);
    return r == CMOX_ECC_SUCCESS && sig_len == 64;
}

/* Vrai si priv et pub forment bien une paire : pub recopiée dans priv, puis signature vérifiée */
static bool key_pair_ok(const auth_key_t *p)
{
    static const uint8_t msg[] = "board_auth selftest";
    uint8_t sig[64];
    uint32_t fault = 0;
    cmox_ecc_handle_t h;

    if (p->priv_len != sizeof p->priv || memcmp(p->priv + 32, p->pub, sizeof p->pub) != 0) {
        return false;
    }
    if (!sign(p->priv, msg, sizeof msg, sig)) {
        return false;
    }
    cmox_ecc_construct(&h, MATH, work, sizeof work);
    cmox_ecc_retval_t r = cmox_eddsa_verify(&h, CURVE, p->pub, sizeof p->pub, msg, sizeof msg,
                                            sig, sizeof sig, &fault);
    cmox_ecc_cleanup(&h);
    return r == CMOX_ECC_AUTH_SUCCESS && fault == CMOX_ECC_AUTH_SUCCESS;
}

/* Écrit la clé, relit, et ne pose le magic qu'une fois la relecture conforme */
static bool key_store(const auth_key_t *src)
{
    FLASH_EraseInitTypeDef er = { .TypeErase = FLASH_TYPEERASE_SECTORS, .Sector = FLASH_SECTOR_7,
                                  .NbSectors = 1, .VoltageRange = FLASH_VOLTAGE_RANGE_3 };
    const uint32_t *w = (const uint32_t *)src;
    uint32_t err;
    bool ok;

    HAL_FLASH_Unlock();
    __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_OPERR | FLASH_FLAG_WRPERR |
                           FLASH_FLAG_PGAERR | FLASH_FLAG_PGPERR | FLASH_FLAG_ERSERR);
    ok = (HAL_FLASHEx_Erase(&er, &err) == HAL_OK);
    for (uint32_t i = 1; ok && i < sizeof *src / 4; i++) {
        ok = (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, KEY_ADDR + 4 * i, w[i]) == HAL_OK);
    }
    flash_sync();
    ok = ok && memcmp((const uint8_t *)KEY_ADDR + 4, (const uint8_t *)src + 4, sizeof *src - 4) == 0;
    if (ok) {
        ok = (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, KEY_ADDR, w[0]) == HAL_OK);
    }
    HAL_FLASH_Lock();
    flash_sync();
    return ok && KEY->magic == KEY_MAGIC;
}

int auth_generate(RNG_HandleTypeDef *hrng, char *out)
{
    uint8_t sig[64];

    if (cmox_initialize(NULL) != CMOX_INIT_SUCCESS) {
        return AUTH_ERR_INIT;
    }
    if (!sign(kat_priv, kat_msg, sizeof kat_msg, sig) || memcmp(sig, kat_sig, sizeof sig) != 0) {
        return AUTH_ERR_CRYPTOLIB;
    }
    flash_sync();

    /* Clé absente, ou présente mais fausse (ex. écrite par une version précédente) : on la (re)crée */
    if (KEY->magic != KEY_MAGIC || !key_pair_ok(KEY)) {
        uint32_t rnd[8];
        size_t priv_len = sizeof k.priv, pub_len = sizeof k.pub;
        cmox_ecc_handle_t h;

        for (int i = 0; i < 8; i++) {
            if (HAL_RNG_GenerateRandomNumber(hrng, &rnd[i]) != HAL_OK) {
                return AUTH_ERR_RNG;
            }
        }
        memset(&k, 0, sizeof k);
        cmox_ecc_construct(&h, MATH, work, sizeof work);
        cmox_ecc_retval_t r = cmox_eddsa_keyGen(&h, CURVE, (uint8_t *)rnd, sizeof rnd,
                                                k.priv, &priv_len, k.pub, &pub_len);
        cmox_ecc_cleanup(&h);
        memset(rnd, 0, sizeof rnd);
        if (r != CMOX_ECC_SUCCESS || priv_len != sizeof k.priv || pub_len != sizeof k.pub) {
            return AUTH_ERR_KEYGEN;
        }
        k.magic = KEY_MAGIC;
        k.priv_len = priv_len;

        bool good = key_pair_ok(&k);
        bool stored = good && key_store(&k);
        memset(&k, 0, sizeof k);
        if (!good) {
            return AUTH_ERR_RAM;
        }
        if (!stored) {
            return AUTH_ERR_FLASH;
        }
    }

    memcpy(out, (const void *)UID_BASE, 12);
    memcpy(out + 12, KEY->pub, 32);
    return 44;
}

int auth_check(const char *in, char *out)
{
    uint8_t msg[8 + 12 + 32];           /* "SMWAUTH1" || UID || nonce */

    if (KEY->magic != KEY_MAGIC) {
        return -1;
    }
    memcpy(msg, "SMWAUTH1", 8);
    memcpy(msg + 8, (const void *)UID_BASE, 12);
    memcpy(msg + 20, in, 32);

    if (!sign(KEY->priv, msg, sizeof msg, (uint8_t *)out + 12)) {
        return -1;
    }
    memcpy(out, msg + 8, 12);
    return 76;
}


```
