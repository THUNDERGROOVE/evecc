#include "bluecrypto.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#include <zlib.h>

BOOL CreatePrivateExponentOneKey(LPTSTR szProvider,
	DWORD dwProvType,
	LPTSTR szContainer,
	DWORD dwKeySpec,
	HCRYPTPROV *hProv,
	HCRYPTKEY *hPrivateKey)
{
	BOOL fReturn = FALSE;
	BOOL fResult;
	uint32_t n;
	LPBYTE keyblob = NULL;
	DWORD dwkeyblob;
	DWORD dwBitLen;
	BYTE *ptr;

	__try {
		//*hProv = 0;
		*hPrivateKey = 0;

		if ((dwKeySpec != AT_KEYEXCHANGE) && (dwKeySpec != AT_SIGNATURE))  __leave;
		// Generate the private key
		fResult = CryptGenKey(*hProv, dwKeySpec, CRYPT_EXPORTABLE, hPrivateKey);
		if (!fResult) __leave;

		// Export the private key, we'll convert it to a private
		// exponent of one key
		fResult = CryptExportKey(*hPrivateKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwkeyblob);
		if (!fResult) __leave;

		keyblob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob);
		if (!keyblob) __leave;

		fResult = CryptExportKey(*hPrivateKey, 0, PRIVATEKEYBLOB, 0, keyblob, &dwkeyblob);
		if (!fResult) __leave;


		CryptDestroyKey(*hPrivateKey);
		*hPrivateKey = 0;

		// Get the bit length of the key
		memcpy(&dwBitLen, &keyblob[12], 4);

		// Modify the Exponent in Key BLOB format
		// Key BLOB format is documented in SDK

		// Convert pubexp in rsapubkey to 1
		ptr = &keyblob[16];
		for (n = 0; n < 4; n++) {
			if (n == 0) ptr[n] = 1;
			else ptr[n] = 0;
		}

		// Skip pubexp
		ptr += 4;
		// Skip modulus, prime1, prime2
		ptr += (dwBitLen / 8);
		ptr += (dwBitLen / 16);
		ptr += (dwBitLen / 16);

		// Convert exponent1 to 1
		for (n = 0; n < (dwBitLen / 16); n++) {
			if (n == 0) ptr[n] = 1;
			else ptr[n] = 0;
		}

		// Skip exponent1
		ptr += (dwBitLen / 16);

		// Convert exponent2 to 1
		for (n = 0; n < (dwBitLen / 16); n++) {
			if (n == 0) ptr[n] = 1;
			else ptr[n] = 0;
		}

		// Skip exponent2, coefficient
		ptr += (dwBitLen / 16);
		ptr += (dwBitLen / 16);

		// Convert privateExponent to 1
		for (n = 0; n < (dwBitLen / 8); n++) {
			if (n == 0) ptr[n] = 1;
			else ptr[n] = 0;
		}

		// Import the exponent-of-one private key.      
		if (!CryptImportKey(*hProv, keyblob, dwkeyblob, 0, 0, hPrivateKey)) {
			__leave;
		}

		fReturn = TRUE;
	}
	__finally {
		if (keyblob) LocalFree(keyblob);

		if (!fReturn) {
			if (*hPrivateKey) CryptDestroyKey(*hPrivateKey);
			if (*hProv) CryptReleaseContext(*hProv, 0);
		}
	}

	return fReturn;
}

char *strlrev(char *p, int len)
{
	char *out = (char *)calloc(1, len);

	for (int i = len; i > 0; i--) {
		out[i] = p[i];
	}
	return out;
}


HCRYPTKEY CryptContext::GetKey(CryptKeyType type) {
	switch (type) {
	case CRYPTKEY_CCP:
		return this->ccp_key;
		break;
    case CRYPTKEY_ROAMING:
        return this->roaming_crypt_key;
	default:
		return NULL;
		break;
	}
}


CryptContext *ctx = NULL;

char *export_plain_session_blob(HCRYPTKEY sessionKey, size_t *blob_size) {
    HCRYPTKEY priv = NULL;
    if (!CreatePrivateExponentOneKey(MS_ENHANCED_PROV, PROV_RSA_FULL, NULL, AT_KEYEXCHANGE, &ctx->context, &priv)) {
        printf(" >> Failed generating exp 1 crypt key\n");
    }

    return smart_export_key(sessionKey, SIMPLEBLOB, blob_size, priv);
}

int init_cryptcontext_gen(char *password) {
    ctx = new CryptContext;
    HCRYPTPROV context = NULL;
	if (!CryptAcquireContextA(&context, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		printf(" >> Failed to acquired cryptographic context\n");
		return -5;
	}
    ctx->context = context;
    ctx->password = password;

    return 0;
}

int init_cryptcontext(char *password) {
	ctx = new CryptContext;
	HCRYPTPROV context = NULL;
	if (!CryptAcquireContextA(&context, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		printf(" >> Failed to acquired cryptographic context\n");
		return -5;
	}
    ctx->context = context;

    if (!import_keys(password)) {
        printf(" >> Failed to import keys!\n");
        return -7;
    }


	return 0;
}

static unsigned char codeCryptKey_orig[] =
        {
                0x01, 0x02, 0x00, 0x00, 0x03, 0x66, 0x00, 0x00, 0x00, 0xA4,
                0x00, 0x00, 0x07, 0x83, 0x08, 0x07, 0xCD, 0x10, 0x10, 0xF8,
                0xF8, 0xE0, 0x5E, 0xB3, 0x91, 0x68, 0x5D, 0xE3, 0x43, 0x25,
                0xF7, 0x4A, 0xA2, 0x52, 0x10, 0x57, 0x00, 0xD6, 0x8F, 0x94,
                0x68, 0x08, 0xAE, 0x04, 0x2C, 0xD8, 0xAE, 0x8B, 0x07, 0xAF,
                0x7C, 0x95, 0x78, 0x6B, 0x3C, 0x2B, 0x79, 0x87, 0x12, 0xDA,
                0x20, 0x4D, 0xD8, 0x10, 0x94, 0x71, 0x6C, 0xD6, 0xF7, 0x31,
                0x12, 0x4B, 0x2B, 0x13, 0xD3, 0x8E, 0x67, 0x63, 0xBE, 0xA5,
                0x62, 0x2D, 0x3F, 0x52, 0x8D, 0x7C, 0x5F, 0xE8, 0x58, 0xB6,
                0xBD, 0xDE, 0xDC, 0x8F, 0x58, 0xB8, 0xD4, 0xFA, 0xB2, 0xDE,
                0xFA, 0xCE, 0x66, 0x9A, 0xA8, 0x39, 0x14, 0x9B, 0xF0, 0x3A,
                0x8D, 0xCA, 0x41, 0x90, 0x39, 0x68, 0x27, 0xC9, 0x94, 0xBA,
                0xE1, 0x40, 0xAA, 0x79, 0x0B, 0x76, 0x2F, 0xCB, 0x70, 0x7F,
                0x8D, 0x0A, 0x37, 0xED, 0x43, 0x9E, 0x94, 0x83, 0x02, 0x00
        };

void setup_signing_context() {

}

bool import_keys(char *password) {


//	if (!CryptImportKey(ctx->context, (BYTE*)codeCryptKey_orig, 140, priv, 0, &key)) {
//		printf(" >> Failed loading crypt key\n");
//		DWORD err = GetLastError();
//        return false;
//	}

#define HasFile(name) !(INVALID_FILE_ATTRIBUTES == GetFileAttributes(name) && GetLastError() == ERROR_FILE_NOT_FOUND)
    if(HasFile(EVECC_ROAMING_KEYS"pub") && HasFile(EVECC_ROAMING_KEYS"priv")/* && HasFile(EVECC_ROAMING_KEYS"crypt")*/) {
//        if (password == NULL) {
//            printf("To use roaming keys, you must supply the password used to generate them --password <password>");
//            exit(-1);
//        }
        // we have EVECC_ROAMING_KEYS available
        printf(" >> roaming keys %s found, loading this as well!\n", EVECC_ROAMING_KEYS);
        ctx->roaming_keys = load_keys_ini();

        HCRYPTKEY priv = NULL;
        if (!CreatePrivateExponentOneKey(MS_ENHANCED_PROV, PROV_RSA_FULL, NULL, AT_KEYEXCHANGE, &ctx->context, &priv)) {
            printf(" >> Failed generating exp 1 crypt key\n");
            DWORD err = GetLastError();
            return false;
        }

        if (!CryptImportKey(ctx->context, (BYTE*)codeCryptKey_orig, 140, priv, 0, &ctx->roaming_crypt_key)) {
            printf(" >> Failed loading crypt key\n");
            DWORD err = GetLastError();
            return false;
        }

        HCRYPTKEY pkey = generate_key_from_password(password, ctx->context);

        if (!CryptImportKey(ctx->context, (BYTE*)ctx->roaming_keys->pub_key, 148, NULL, 0, &ctx->roaming_pub)) {
            printf(" >> Failed loading crypt key\n");
            DWORD err = GetLastError();
            return false;
        }



        if (!CryptImportKey(ctx->context, (BYTE*)ctx->roaming_keys->priv_key, 596, pkey, 0, &ctx->roaming_priv)) {
            printf(" >> Failed loading private key\n");
            GetLastError();
            return false;
        }



        setup_signing_context();
    } else {
        printf(" !! no keys\n");
        exit(-11);
    }

//	ctx->ccp_key = key;
    return true;
}

char *SignData(char *data, uint32_t data_size, uint32_t *out_size, char *password) {
    if (ctx->set_key_type == CRYPTKEY_NO_CRYPTO) {
        return strdup("lol eat butt");
    }

    HCRYPTPROV context = NULL;
    if (!CryptAcquireContextA(&context, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        exit(1);
    }
    HCRYPTKEY pkey = generate_key_from_password(password, context);

    HCRYPTKEY key = NULL;
    if (!CryptImportKey(context, (const BYTE*)ctx->roaming_keys->priv_key, ctx->roaming_keys->priv_key_size, pkey, 0, &key)) {
        printf(" >> Failed to import key\n");
        DWORD err = GetLastError();
        *out_size = err;
        return NULL;
    }

    HCRYPTHASH hash = NULL;
	if (!CryptCreateHash(context, CALG_SHA, NULL, 0, &hash)) {
		printf(" >> Failed to create hash\n");
		DWORD err = GetLastError();
		*out_size = err;
		return NULL;
	}

	if (!CryptHashData(hash, (BYTE *)data, data_size, 0)) {
		printf(" >> Failed to hash data\n");
		DWORD err = GetLastError();
		*out_size = err;
		return NULL;
	}

	uint32_t sig_size = 0;
	if (!CryptSignHashA(hash, AT_SIGNATURE, NULL, 0, NULL, (DWORD *)&sig_size)) {
		printf(" >> Failed to determine signature size\n");
		DWORD err = GetLastError();
		*out_size = err;
		return NULL;
	}

	char *signature = (char *)calloc(1, sig_size);

	if (!CryptSignHashA(hash, AT_SIGNATURE, NULL, 0, (BYTE *)signature, (DWORD *)&sig_size)) {
		printf(" >> Failed to determine signature size\n");
		DWORD err = GetLastError();
		*out_size = err;
		return NULL;
	}

	*out_size = sig_size;

	return signature;
}


char *memdup(const char *input, uint32_t size) {
    char *o = (char *)calloc(size, sizeof(char));
    memcpy(o, input, size);
    return o;
}

char *JumbleString(const char *input, uint32_t input_size, uint32_t *read_bytes, CryptKeyType key_type, bool zip) {

	uint32_t total_out = compressBound(input_size);
	char *tmp_out = (char *)calloc(1, total_out);
	if (zip) {
		z_stream info = { 0 };

		info.zalloc = Z_NULL;
		info.zfree = Z_NULL;
		info.opaque = Z_NULL;
		info.avail_in = input_size;
		info.next_in = (Bytef *)input;
		info.avail_out = total_out;
		info.next_out = (Bytef *)tmp_out;

		int err;


		err = deflateInit(&info, 6);
		if (err == Z_OK) {
			err = deflate(&info, Z_FINISH);
			if (err == Z_OK ||
				err == Z_STREAM_END) {
				total_out = info.total_out;
			} else {
				*read_bytes = err;
				return NULL;
			}
		}
		//inflateEnd(&info);
	}

    if (ctx->set_key_type == CRYPTKEY_NO_CRYPTO) {
        *read_bytes = total_out;
        return tmp_out;
    }

	uint32_t encrypted_size = total_out;
    HCRYPTKEY key = ctx->GetKey(key_type);
	if (!CryptEncrypt(key, 0, true, 0, NULL, (DWORD *)&total_out, total_out)) {
		printf(" >> Failed to decrypt\n");
		DWORD err = GetLastError();
		*read_bytes = err;
		return NULL;
	}

	char *real_out = (char *)calloc(1, total_out);
	memcpy(real_out, tmp_out, encrypted_size);
	free(tmp_out);

	uint32_t total_in = encrypted_size;

	if (!CryptEncrypt(ctx->GetKey(key_type), 0, true, 0, (BYTE *)real_out, (DWORD *)&total_in, total_out)) {
		printf(" >> Failed to decrypt\n");
		DWORD err = GetLastError();
		*read_bytes = err;
		return NULL;
	}
	*read_bytes = total_in;
	return real_out;
}

#include <strsafe.h>

void ErrorExit(LPTSTR lpszFunction) {
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
			      FORMAT_MESSAGE_FROM_SYSTEM |
			      FORMAT_MESSAGE_IGNORE_INSERTS,
		      NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		      (LPTSTR)&lpMsgBuf, 0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
					  (lstrlen((LPCTSTR)lpMsgBuf) +
					   lstrlen((LPCTSTR)lpszFunction) +
					   40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
			LocalSize(lpDisplayBuf) / sizeof(TCHAR),
			TEXT("%s failed with error %d: %s"), lpszFunction, dw,
			lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}

uint32_t
UnjumbleString(const char *input, uint32_t input_size, char *output, uint32_t output_size, CryptKeyType key_type,
               bool zip) {

    if (ctx->set_key_type == CRYPTKEY_NO_CRYPTO) {
        memcpy(output, input, input_size);
        return input_size;
    }

	char *real_input = (char *)calloc(1, input_size);
	memcpy(real_input, input, input_size);

	uint32_t decrypted_size = input_size;

	uint32_t val =
		CryptDecrypt(ctx->GetKey(key_type), 0, true, 0,
			     (BYTE *)real_input, (DWORD *)&decrypted_size);

	if (!val) {

		printf(" >> Failed to decrypt\n");
		ErrorExit(TEXT("CryptDecrypt"));
		DWORD err = GetLastError();
		DebugBreak();
		return -8;
	}


	if (zip) {
		z_stream info = { 0 };
		info.total_in = decrypted_size;
		info.avail_in = decrypted_size;
		info.total_out = output_size;
		info.avail_out = output_size;

		info.next_in = (Bytef *)real_input;
		info.next_out = (Bytef *)output;

		int err;
		int ret;

		err = inflateInit(&info);
		if (err == Z_OK) {
			err = inflate(&info, Z_FINISH);
			if (err == Z_OK ||
				err == Z_STREAM_END) {
				ret = info.total_out;
			} else {
				return err;
			}
		}
		inflateEnd(&info);
		free(real_input);
		return info.total_out;
	}
	free(real_input);
	return -100;
}

HCRYPTKEY generate_key_from_password(char *password, HCRYPTPROV context) {
    if (password == NULL) {
        return NULL;
    }
    printf(" >> generating base key from password\n");
    HCRYPTHASH hash = NULL;
    if (!CryptCreateHash(context, CALG_SHA, NULL, NULL, &hash)) {
        printf(" >> Failed to create hasher\n");
        exit(-1);
    }
    if (!CryptHashData(hash, (const BYTE *)password, strlen(password), 0)) {
        printf(" >> Failed to hash password\n");
        exit(-1);
    }
    HCRYPTKEY key;
    if (!CryptDeriveKey(context, CALG_RC4, hash, 0, &key)) {
        printf(" >> Failed to derive key from password hash\n");
        exit(-1);
    }
    return key;
}


// free me!
char *smart_export_key(HCRYPTKEY key, DWORD blobtype, size_t *out_size, HCRYPTKEY expKey) {
    DWORD size = 0;
    CryptExportKey(key, expKey,blobtype, 0, NULL,&size);
    BYTE *out = (BYTE *)calloc(size, sizeof(BYTE));
    if (!CryptExportKey(key, expKey,blobtype, 0, out,&size)) {
         printf(" >> smart_export_key failed to export key\n");
        exit(-1);
    }

    *out_size = size;

    return (char *)out;
}

#define SIGLEN 1024
#define CRYPTLEN 168

#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include "INIReader.h"

std::vector<char> hex_bytes(const std::string& hex) {
    std::vector<char> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = (char) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

std::string hex_string(char *data, int len) {
    std::stringstream ss;
    ss << std::hex;

    for (int i = 0; i < len; i++) {
        ss << std::setw(2) << std::setfill('0') << (int)data[i];
    }

    return ss.str();
}


bool write_keys_ini(char *pub_key, size_t pub_key_size, char *priv_key, size_t priv_key_size, char *crypt_blob, size_t crypt_blob_size) {
    FILE *f = fopen(EVECC_ROAMING_KEYS"pub", "wb");
    fwrite(pub_key, pub_key_size, 1, f);
    fflush(f);
    fclose(f);

    f = fopen(EVECC_ROAMING_KEYS"priv", "wb");
    fwrite(priv_key, priv_key_size, 1, f);
    fflush(f);
    fclose(f);
    /*
    f = fopen(EVECC_ROAMING_KEYS"crypt", "wb");
    fwrite(crypt_blob, crypt_blob_size, 1, f);
    fflush(f);
    fclose(f);
     */

    return true;
}

keys_blob *load_keys_ini() {
    keys_blob *keys = new keys_blob;


    FILE *f = fopen(EVECC_ROAMING_KEYS"pub", "rb");
    fseek(f, 0, SEEK_END);
    keys->pub_key_size = ftell(f);
    rewind(f);
    keys->pub_key = (char *)calloc(keys->pub_key_size, sizeof(char));
    fread(keys->pub_key, keys->pub_key_size, sizeof(char), f);
    fclose(f);

    f = fopen(EVECC_ROAMING_KEYS"priv", "rb");
    fseek(f, 0, SEEK_END);
    keys->priv_key_size= ftell(f);
    rewind(f);
    keys->priv_key = (char *)calloc(keys->priv_key_size, sizeof(char));
    fread(keys->priv_key, keys->priv_key_size, sizeof(char), f);
    fclose(f);

    /*
    f = fopen(EVECC_ROAMING_KEYS"crypt", "rb");
    fseek(f, 0, SEEK_END);
    keys->crypt_blob_size = ftell(f);
    rewind(f);
    keys->crypt_blob = (char *)calloc(keys->crypt_blob_size, sizeof(char));
    fread(keys->crypt_blob, keys->crypt_blob_size, sizeof(char), f);
    fclose(f);
     */

    return keys;
}

bool make_code_accessors(char *password) {
    /* @TODO(np): for now, evecc only supports reusing CCP's original crypt key
        with the current patches in place, we can load code correctly assuming that a new private/public key has been
        generated, and that public key has been injected into the client.
    */
    HCRYPTKEY pkey = generate_key_from_password(password, ctx->context);
    HCRYPTKEY sig;
    printf(" >> beginning generation of signing keys\n");
    if (!CryptGenKey(ctx->context, AT_SIGNATURE, SIGLEN << 16 | CRYPT_EXPORTABLE, &sig)) {
        printf(" >> failed to generate signing key pair\n");
        return false;
    }
    size_t pub_key_size = 0;
    size_t priv_key_size = 0;
    printf(" >> exporting public key..\n");
    char *pub_key = smart_export_key(sig, PUBLICKEYBLOB, &pub_key_size, NULL);
    printf(" >> exporting private key..\n");
    char *priv_key = smart_export_key(sig, PRIVATEKEYBLOB, &priv_key_size, pkey);

    /*
    Currently we can't use our own crypt key - the client is failing to accept it for unknown reasons
     HCRYPTKEY crypt;
    if (!CryptGenKey(ctx->context, CALG_3DES, CRYPTLEN << 16 | CRYPT_EXPORTABLE, &crypt)) {
        printf(" >> failed to generate crypt key\n");
        return false;
    }
    size_t crypt_blob_size = 0;
    char *crypt_blob = export_plain_session_blob(crypt, &crypt_blob_size);
     */

    size_t crypt_blob_size = 0;
    char *crypt_blob = NULL;

    return write_keys_ini(pub_key, pub_key_size, priv_key, priv_key_size, crypt_blob, crypt_blob_size);
}
