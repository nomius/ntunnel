
/* vim: set sw=4 sts=4 tw=80 */

/*
 * Copyright (c) 2012 , David B. Cortarello <dcortarello@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by David B. Cortarello.
 * 4. Neither the name of David B. Cortarello nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID B. CORTARELLO 'AS IS' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL DAVID B. CORTARELLO BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/blowfish.h>
#include "rsa.h"

int LoadPublicKeyFromFile(const char *keyfile, RSA **key, char *MsgNotSet)
{
	FILE *f = NULL;

	if ((f = fopen(keyfile, "r")) == NULL) {
		fprintf(stderr, "LoadPublicKeyFromFile : fopen : %s\n", strerror(errno));
		return 1;
	}

	if ((*key = PEM_read_RSA_PUBKEY(f, NULL, NULL, NULL)) == NULL) {
		fclose(f);
		fprintf(stderr, "LoadPublicKeyFromFile : PEM_read_RSA_PUBKEY() : %s\n", ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}

	fclose(f);
	return 0;
}

int LoadPrivateKeyFromFile(const char *keyfile, RSA **priv, char *MsgNotSet)
{
	FILE *f = NULL;

	if ((f = fopen(keyfile, "r")) == NULL) {
		fprintf(stderr, "LoadPrivateKeyFromFile : fopen : %s\n", strerror(errno));
		return 1;
	}

	if ((*priv = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL)) == NULL) {
		fprintf(stderr, "LoadPrivateKeyFromFile : PEM_read_RSAPrivateKey() : %s\n", ERR_error_string(ERR_get_error(), NULL));
		fclose(f);
		return 1;
	}

	fclose(f);
	return 0;
}

int EncryptMessageWithPublicKey(RSA *key, unsigned char *msg, int len, unsigned char *out, int *olen)
{
	if ((*olen = RSA_public_encrypt(len, msg, out, key, RSA_PKCS1_OAEP_PADDING)) < 0) {
		fprintf(stderr, "EncryptMessageWithPublicKey : RSA_private_encrypt : %s\n", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	return 0;
}

int DecryptMessageWithPrivateKey(RSA *priv, unsigned char *msg, int len, unsigned char *out, int *olen)
{
	if ((*olen = RSA_private_decrypt(len, msg, out, priv, RSA_PKCS1_OAEP_PADDING)) < 0) {
		fprintf(stderr, "DecryptMessageWithPrivateKey : RSA_private_decrypt : %s\n", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	return 0;
}

int SignMessage(RSA *key, unsigned char *msg, int len, unsigned char *out, unsigned int *olen)
{
	unsigned char hash[20];

	if (!SHA1(msg, len, hash)) {
		fprintf(stderr, "SignMessage : SHA1 : %s\n", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	if (!RSA_sign(NID_sha1, hash, sizeof(hash), out, olen, key)) {
		fprintf(stderr, "SignMessage : SHA1_sign : %s\n", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	return *olen;
}

int VerifyMessage(RSA *key, unsigned char *msg, int len, unsigned char *signature, int siglen)
{
	unsigned char hash[20];

	if (!SHA1(msg, len, hash)) {
		fprintf(stderr, "VerifyMessage : SHA1 : %s\n", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	if (!RSA_verify(NID_sha1, hash, sizeof(hash), signature, siglen, key))
		return 1;

	return 0;
}

