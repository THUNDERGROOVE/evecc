#pragma once

#include <Windows.h>
#include <wincrypt.h>
#include <stdint.h>

#define EVECC_ROAMING_KEYS "evecc.keys."
#define CCP_KEYS "ccp.keys."

enum CryptKeyType {
	CRYPTKEY_CCP,
    CRYPTKEY_ROAMING,
};

static char *key_types[] = {
        "ccp",
        "roaming",
        NULL,
};
struct keys_blob {
    char *pub_key;
    char *priv_key;
    char *crypt_blob;
    size_t pub_key_size;
    size_t priv_key_size;
    size_t crypt_blob_size;
    keys_blob();
    void dump(char *prefix);
};

struct CryptContext {
    char *password;
    CryptKeyType set_key_type;
	HCRYPTPROV context;
    HCRYPTPROV sign_context;
	HCRYPTKEY ccp_key;
    HCRYPTKEY roaming_crypt_key;
	HCRYPTKEY GetKey(CryptKeyType type);
    keys_blob *roaming_keys;
    HCRYPTKEY roaming_priv;
    HCRYPTKEY roaming_pub;
    keys_blob *ccp_keys;
    HCRYPTKEY ccp_crypt_key;
};

extern CryptContext *ctx;

int init_cryptcontext(char *password);
int init_cryptcontext_gen(char *password);
char *SignData(char *data, uint32_t data_size, uint32_t *out_size, char *password);

uint32_t UnjumbleString(const char *input, uint32_t input_size, char *output, uint32_t output_size,
                        CryptKeyType key_type, bool zip = true);

char *JumbleString(const char *input, uint32_t input_size, uint32_t *read_bytes, CryptKeyType key_type,
                   bool zip = true);
bool make_code_accessors(char *password, char *keyFile);
char *smart_export_key(HCRYPTKEY key, DWORD blobtype, size_t *out_size, HCRYPTKEY expKey);
bool import_keys(char *password);
keys_blob *load_keys_blob(char *prefix);
bool make_code_accessors(char *password);
HCRYPTKEY generate_key_from_password(char *password, HCRYPTPROV context);

CryptKeyType parse_key_type(char *type);
