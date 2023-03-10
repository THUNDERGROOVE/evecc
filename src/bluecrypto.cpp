#include "bluecrypto.h"
#include "util.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#include "zlib.h"
#include <loguru/loguru.hpp>

#pragma comment(lib, "python27.lib")

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

HCRYPTKEY CryptContext::GetKey(CryptKeyType type) {
	switch (type) {
	case CRYPTKEY_CCP:
		return this->ccp_key;
		break;
    case CRYPTKEY_ROAMING:
        return this->ccp_crypt_key;
	default:
		return NULL;
		break;
	}
}


CryptContext *ctx = NULL;

char *export_plain_session_blob(HCRYPTKEY sessionKey, size_t *blob_size) {
    HCRYPTKEY priv = NULL;
    if (!CreatePrivateExponentOneKey(MS_ENHANCED_PROV, PROV_RSA_FULL, NULL, AT_KEYEXCHANGE, &ctx->context, &priv)) {
        std::string err = get_last_error_string();
        LOG_F(ERROR, "failed to create exponent of one key: %s", err.c_str());
        exit(-1);
    }

    return smart_export_key(sessionKey, SIMPLEBLOB, blob_size, priv);
}

int init_cryptcontext_gen(char *password) {
    ctx = new CryptContext;
    HCRYPTPROV context = NULL;
	if (!CryptAcquireContextA(&context, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        std::string err = get_last_error_string();
        LOG_F(ERROR, "failed to acquire cryptographic context: %s", err.c_str());
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
        std::string err = get_last_error_string();
		LOG_F(ERROR,"failed to acquire cryptographic context: %s", err.c_str());
		return -5;
	}
    ctx->context = context;

    if (!import_keys(password)) {
        LOG_F(ERROR, "failed to import keys!");
        return -7;
    }


	return 0;
}

bool import_keys(char *password) {
    if(HasFile(CCP_KEYS"crypt")) {
        ctx->ccp_keys = load_keys_blob(CCP_KEYS);
        HCRYPTKEY priv = NULL;
        if (!CreatePrivateExponentOneKey(MS_ENHANCED_PROV, PROV_RSA_FULL, NULL, AT_KEYEXCHANGE, &ctx->context, &priv)) {
            std::string err = get_last_error_string();
            LOG_F(ERROR,"failed to create exponent of one key: %s", err.c_str());
            return false;
        }
        LOG_F(INFO, "successfully created exponent of one key");

        if (!CryptImportKey(ctx->context, (BYTE *)ctx->ccp_keys->crypt_blob, ctx->ccp_keys->crypt_blob_size, priv, 0, &ctx->ccp_crypt_key)) {
            std::string err = get_last_error_string();
            LOG_F(ERROR, "failed loading crypt key: %s", err.c_str());
            return false;
        }
        LOG_F(INFO, "successfully loaded CCP crypt key blob");
    } else {
        LOG_F(ERROR, "you must first dump CCP's keys with --dump-keys <path to blue.dll>");
        exit(-12);
    }
    if(HasFile(EVECC_ROAMING_KEYS"pub") && HasFile(EVECC_ROAMING_KEYS"priv")) {
        LOG_F(INFO," roaming keys %s found, loading this as well!", EVECC_ROAMING_KEYS);
        ctx->roaming_keys = load_keys_blob(EVECC_ROAMING_KEYS);

        HCRYPTKEY pkey = generate_key_from_password(password, ctx->context);

        if (!CryptImportKey(ctx->context, (BYTE*)ctx->roaming_keys->pub_key, 148, NULL, 0, &ctx->roaming_pub)) {
            std::string err = get_last_error_string();
            LOG_F(ERROR,"failed loading public key: %s", err.c_str());
            return false;
        }
        LOG_F(INFO, "successfully loaded roaming public key blob");

        if (!CryptImportKey(ctx->context, (BYTE*)ctx->roaming_keys->priv_key, 596, pkey, 0, &ctx->roaming_priv)) {
            std::string err = get_last_error_string();
            LOG_F(ERROR,"failed loading private key: %s", err.c_str());
            return false;
        }
        LOG_F(INFO, "successfully loaded roaming private key blob");
    } else {
        LOG_F(ERROR, "you must first generate an RSA key pair with --gen-key");
        exit(-11);
    }

    return true;
}

char *SignData(char *data, uint32_t data_size, uint32_t *out_size, char *password) {
    HCRYPTPROV context = NULL;
    if (!CryptAcquireContextA(&context, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        std::string err = get_last_error_string();
        LOG_F(ERROR, "failed to acquire cryptographic context: %s", err.c_str());
        exit(1);
    }
    HCRYPTKEY pkey = generate_key_from_password(password, context);

    HCRYPTKEY key = NULL;
    if (!CryptImportKey(context, (const BYTE*)ctx->roaming_keys->priv_key, ctx->roaming_keys->priv_key_size, pkey, 0, &key)) {
        std::string err = get_last_error_string();
        LOG_F(ERROR, "failed to import key: %s", err.c_str());
        *out_size = -1;
        return NULL;
    }

    HCRYPTHASH hash = NULL;
	if (!CryptCreateHash(context, CALG_SHA, NULL, 0, &hash)) {
        std::string err = get_last_error_string();
		LOG_F(ERROR,"failed to create hash: %s", err.c_str());
		*out_size = -1;
		return NULL;
	}

	if (!CryptHashData(hash, (BYTE *)data, data_size, 0)) {
        std::string err = get_last_error_string();
		LOG_F(ERROR,"failed to hash data: %s", err.c_str());
		return NULL;
	}

	uint32_t sig_size = 0;
	if (!CryptSignHashA(hash, AT_SIGNATURE, NULL, 0, NULL, (DWORD *)&sig_size)) {
        std::string err = get_last_error_string();
		LOG_F(ERROR,"failed to determine signature size: %s", err.c_str());
		*out_size = -1;
		return NULL;
	}

	char *signature = (char *)calloc(1, sig_size);

	if (!CryptSignHashA(hash, AT_SIGNATURE, NULL, 0, (BYTE *)signature, (DWORD *)&sig_size)) {
        std::string err = get_last_error_string();
		LOG_F(ERROR,"failed to determine signature size: %s", err.c_str());
		*out_size = -1;
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

	uint32_t encrypted_size = total_out;
    HCRYPTKEY key = ctx->GetKey(key_type);
	if (!CryptEncrypt(key, 0, true, 0, NULL, (DWORD *)&total_out, total_out)) {
        std::string err = get_last_error_string();
		LOG_F(ERROR,"failed to decrypt: %s", err.c_str());
		*read_bytes = -1;
		return NULL;
	}

	char *real_out = (char *)calloc(1, total_out);
	memcpy(real_out, tmp_out, encrypted_size);
	free(tmp_out);

	uint32_t total_in = encrypted_size;

	if (!CryptEncrypt(ctx->GetKey(key_type), 0, true, 0, (BYTE *)real_out, (DWORD *)&total_in, total_out)) {
        std::string err = get_last_error_string();
		LOG_F(ERROR,"failed to decrypt: %s", err.c_str());
		*read_bytes = -1;
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

	char *real_input = (char *)calloc(1, input_size);
	memcpy(real_input, input, input_size);

	uint32_t decrypted_size = input_size;

	uint32_t val =
		CryptDecrypt(ctx->GetKey(key_type), 0, true, 0,
			     (BYTE *)real_input, (DWORD *)&decrypted_size);

	if (!val) {
        std::string err = get_last_error_string();
		LOG_F(ERROR,"failed to decrypt: %s", err.c_str());
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
    LOG_F(INFO,"generating base key from password");
    HCRYPTHASH hash = NULL;
    if (!CryptCreateHash(context, CALG_SHA, NULL, NULL, &hash)) {
        std::string err = get_last_error_string();
        LOG_F(ERROR,"failed to create hasher: %s", err.c_str());
        exit(-1);
    }
    if (!CryptHashData(hash, (const BYTE *)password, strlen(password), 0)) {
        std::string err = get_last_error_string();
        LOG_F(INFO,"failed to hash password: %s", err.c_str());
        exit(-1);
    }
    HCRYPTKEY key;
    if (!CryptDeriveKey(context, CALG_RC4, hash, 0, &key)) {
        std::string err = get_last_error_string();
        LOG_F(ERROR,"failed to derive key from password hash: %s", err.c_str());
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
        std::string err = get_last_error_string();
        LOG_F(ERROR," >> smart_export_key failed to export key: %s", err.c_str());
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

keys_blob *load_keys_blob(char *prefix) {
    LOG_F(INFO,"loading keys blobs for prefix: %s", prefix);
    keys_blob *keys = new keys_blob;
    std::string base = std::string(prefix);
    std::string pub_name = base + "pub";
    std::string priv_name = base + "priv";
    std::string crypt_name = base + "crypt";

    if (HasFile(pub_name.c_str())) {
        LOG_F(INFO,"loading public key: %s", pub_name.c_str());
        FILE *f = fopen(pub_name.c_str(), "rb");
        fseek(f, 0, SEEK_END);
        keys->pub_key_size = ftell(f);
        rewind(f);
        keys->pub_key = (char *) calloc(keys->pub_key_size, sizeof(char));
        fread(keys->pub_key, keys->pub_key_size, sizeof(char), f);
        fclose(f);
    }

    if (HasFile(priv_name.c_str())) {
        LOG_F(INFO,"loading private key: %s", priv_name.c_str());
        FILE *f = fopen(priv_name.c_str(), "rb");
        fseek(f, 0, SEEK_END);
        keys->priv_key_size = ftell(f);
        rewind(f);
        keys->priv_key = (char *) calloc(keys->priv_key_size, sizeof(char));
        fread(keys->priv_key, keys->priv_key_size, sizeof(char), f);
        fclose(f);
    }

    if (HasFile(crypt_name.c_str())) {
        LOG_F(INFO," > loading crypt key: %s", crypt_name.c_str());
        FILE *f = fopen(crypt_name.c_str(), "rb");
        fseek(f, 0, SEEK_END);
        keys->crypt_blob_size = ftell(f);
        rewind(f);
        keys->crypt_blob = (char *)calloc(keys->crypt_blob_size, sizeof(char));
        fread(keys->crypt_blob, keys->crypt_blob_size, sizeof(char), f);
        fclose(f);
    }

    return keys;
}

bool make_code_accessors(char *password) {
    /* @TODO(np): for now, evecc only supports reusing CCP's original crypt key
        with the current patches in place, we can load code correctly assuming that a new private/public key has been
        generated, and that public key has been injected into the client.
    */
    HCRYPTKEY pkey = generate_key_from_password(password, ctx->context);
    HCRYPTKEY sig;
    LOG_F(INFO,"beginning generation of signing keys");
    if (!CryptGenKey(ctx->context, AT_SIGNATURE, SIGLEN << 16 | CRYPT_EXPORTABLE, &sig)) {
        std::string err = get_last_error_string();
        LOG_F(ERROR, " >> failed to generate signing key pair: %s", err.c_str());
        return false;
    }
    size_t pub_key_size = 0;
    size_t priv_key_size = 0;
    keys_blob *keys = new keys_blob;

    LOG_F(INFO,"exporting public key..");
    keys->pub_key = smart_export_key(sig, PUBLICKEYBLOB, &keys->pub_key_size, NULL);
    LOG_F(INFO,"exporting private key..");
    keys->priv_key = smart_export_key(sig, PRIVATEKEYBLOB, &keys->priv_key_size, pkey);

    keys->dump(EVECC_ROAMING_KEYS);
    return true;
}

keys_blob::keys_blob() {
    memset(this, 0, sizeof(*this));
}

void keys_blob::dump(char *prefix) {
    LOG_F(INFO,"dumping keys with prefix: %s", prefix);
    std::string base = std::string(prefix);
    std::string pub_filename = base + "pub";
    std::string priv_filename = base + "priv";
    std::string crypt_filename = base + "crypt";
    if (pub_key != NULL) {
        LOG_F(INFO,"dumping public key: %s", pub_filename.c_str());
        FILE *f = fopen(pub_filename.c_str(), "wb");
        fwrite(pub_key, pub_key_size, 1, f);
        fflush(f);
        fclose(f);
    }
    if (this->priv_key != NULL) {
        LOG_F(INFO,"dumping private key: %s", priv_filename.c_str());
        FILE *f = fopen(priv_filename.c_str(), "wb");
        fwrite(this->priv_key, this->priv_key_size, 1, f);
        fflush(f);
        fclose(f);
    }
    if (this->crypt_blob != NULL) {
        LOG_F(INFO,"dumping crypt key: %s", crypt_filename.c_str());
        FILE *f = fopen(crypt_filename.c_str(), "wb");
        fwrite(this->crypt_blob, this->crypt_blob_size, 1, f);
        fflush(f);
        fclose(f);
    }
}

CryptKeyType parse_key_type(char *type) {
    if (type == NULL) {
        return CRYPTKEY_ROAMING;
    }
    int i = 0;
    while (true) {
        if (key_types[i] == NULL) {
            break;
        }
        if (strcmp(key_types[i], type) == 0) {
            return (CryptKeyType)i;
        }
        i++;
    }
    return CRYPTKEY_ROAMING;
}
