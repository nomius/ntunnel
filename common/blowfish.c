
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
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/blowfish.h>

void CryptoInit(EVP_CIPHER_CTX *ctx, unsigned char *PrivKey, unsigned char **IV)
{
	*IV = PrivKey + 16;
	EVP_CIPHER_CTX_init(ctx);
}

int do_decrypt(EVP_CIPHER_CTX *ctx, unsigned char *PrivKey, unsigned char *IV, unsigned char *in, int ilen, unsigned char *out, int *olen)
{
	int tlen = 0;

	if (!EVP_DecryptInit(ctx, EVP_bf_cbc(), PrivKey, IV)) {
		fprintf(stderr, "do_encrypt : EVP_DecryptInit : %s\n", ERR_error_string(0, NULL));
		return -1;
	}

	if (!EVP_DecryptUpdate(ctx, out, olen, in, ilen)) {
		fprintf(stderr, "do_decrypt : EVP_DecryptUpdate : %s\n", ERR_error_string(0, NULL));
		return -1;
	}

	if (!EVP_DecryptFinal(ctx, out + *olen, &tlen)) {
		fprintf(stderr, "do_decrypt : EVP_DecryptFinal : %s\n", ERR_error_string(0, NULL));
		return -1;
	}
	*olen += tlen;

	return 0;
}

int do_encrypt(EVP_CIPHER_CTX *ctx, unsigned char *PrivKey, unsigned char *IV, unsigned char *in, int ilen, unsigned char *out, int *olen)
{
	int tlen = 0;

	if (!EVP_EncryptInit(ctx, EVP_bf_cbc(), PrivKey, IV)) {
		fprintf(stderr, "do_encrypt : EVP_EncryptInit : %s\n", ERR_error_string(0, NULL));
		return -1;
	}
	if (!EVP_EncryptUpdate(ctx, out, olen, in, ilen)) {
		fprintf(stderr, "do_encrypt : EVP_EncryptUpdate : %s\n", ERR_error_string(0, NULL));
		return -1;
	}

	if (!EVP_EncryptFinal(ctx, out + *olen, &tlen)) {
		fprintf(stderr, "do_encrypt : EVP_EncryptFinal : %s\n", ERR_error_string(0, NULL));
		return -1;
	}

	*olen += tlen;

	return 0;
}


