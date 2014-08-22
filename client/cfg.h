
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
#include <netinet/in.h>

#define KEYSIZE 24

typedef struct _ntconf {
	char *ip;                /* IP address */
	char *brd;               /* Broadcast address */
	char *msk;               /* Network mask */
	char *mtu;               /* MTU... (Does this make any sence today?) */
	struct sockaddr_in data; /* Raw information for fast comparition */
} NetConf4;

typedef struct _sconf {
	char *ConnectionID;   /* My Connection ID (argv[2]) */
	char *type;           /* Client's tun/tap type */
	char *ifname;         /* Client's interface name */
	char *host;           /* Server's host */
	char *port;           /* Server's UDP port */
	char *fprivkey;       /* Client's private key */
	char *fpubkey;        /* Client's public key */
	char *fsrvpubkey;     /* Server's public key */
	char *cfgfile;        /* Client's configuration file name */
	NetConf4 ns;          /* Client's network setup provided by the server */
	RSA *priv;            /* Client's private key */
	RSA *pub;             /* Client's public key */
	RSA *srv;             /* Server's public key */
	unsigned char PrivKey[KEYSIZE]; /* Client's blowfish encryption key */
	unsigned char *IV;
	EVP_CIPHER_CTX ctx;
} ClientConf;

int ReadClientSetup(const char *cfgfile, char *ConnectionID);

#endif
