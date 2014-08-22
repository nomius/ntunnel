
/* vim: set sw=4 sts=4 tw=80 */

/*
 * Copyright (c) 2011 , David B. Cortarello <dcortarello@gmail.com>
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

#ifndef CFG_H
#define CFG_H

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/blowfish.h>

#define KEYSIZE 24

typedef struct _ntconf {
	char *ip;                /* IP address */
	char *brd;               /* Broadcast address */
	char *msk;               /* Network mask */
	struct sockaddr_in data; /* Raw information for fast comparition */
} NetConf4;

typedef struct _sconf {
	char *type;           /* Server's tun/tap type */
	char *ifname;         /* Server's interface name */
	char *port;           /* Server's UDP listener port */
	char *fprivkey;       /* Server's private key */
	char *fpubkey;        /* Server's public key */
	char *cfgfile;        /* Server's configuration file name */
	NetConf4 ns;          /* Server's network setup */
	RSA *priv;            /* Server's private key */
	RSA *pub;             /* Server's public key */
} ServerConf;

typedef struct _cconf {
	char *fpubkey;      /* Client's public key */
	char *ConnectionID; /* Client's ID */
	unsigned char PrivKey[KEYSIZE]; /* Client's blowfish encryption key */
	unsigned char *IV;
	EVP_CIPHER_CTX ctx;
	RSA *pub;           /* Client's public key */
	NetConf4 ns;        /* Client's network setup */
} ClientConf;


char *ReadServerSetup(const char *cfgfile);
ClientConf *ReadClientConf(const char *cfgfile, const char *ConnectionID);

#endif
