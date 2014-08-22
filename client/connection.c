
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
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <openssl/evp.h>
#include "unix.h"
#include "rsa.h"
#include "blowfish.h"
#include "rsa.h"
#include "cfg.h"

#define MIN_BUF 16
#define MED_BUF 128

#define LOAD_PRIVATE_KEYFILE_ERR(x) x" not set. You can create a KeyPair with:\n" \
                                     " openssl genrsa -out PRIVATE_KEY.pem 1024\n" \
                                     " openssl rsa -in PRIVATE_KEY.pem -pubout > PUBLIC_KEY.pem\n"


#define LOAD_SRV_PUBLIC_KEYFILE_ERR(x)  "Failed to load " x ". Can't load client's public key."

extern ClientConf Setup;

int DoAuthenticateClient(int netfd, struct sockaddr_in *srv)
{
	unsigned char cr_buffer[BUFSIZ], dcr_buffer[BUFSIZ], signature[MED_BUF];
	int dcr_size = 0, cr_size = 0, siglen = 0;

	memset(dcr_buffer, 0, sizeof(dcr_buffer));

	/* Send an empty message to start the connection and then the ConnectionID */
	if (WriteH(netfd, (struct sockaddr *)srv, "", 0) < 0) {
		fprintf(stderr, "DoAuthenticateClient : WriteH\n");
		return -1;
	}
	if (WriteH(netfd, (struct sockaddr *)srv, Setup.ConnectionID, strlen(Setup.ConnectionID)) < 0) {
		fprintf(stderr, "DoAuthenticateClient : WriteH\n");
		return -1;
	}

	/* Wait for the message and the signature */
	if ((cr_size = ReadN(netfd, (struct sockaddr *)srv, cr_buffer, BUFSIZ)) <= 0) {
		fprintf(stderr, "DoAuthenticateClient : ReadN\n");
		return -1;
	}
	if ((siglen = ReadN(netfd, (struct sockaddr *)srv, signature, MED_BUF)) <= 0) {
		fprintf(stderr, "DoAuthenticateClient : ReadN\n");
		return -1;
	}

	/* Decrypt the message  and verify the signature */
	if (DecryptMessageWithPrivateKey(Setup.priv, cr_buffer, cr_size, dcr_buffer, &dcr_size)) {
		fprintf(stdout, "Authentication failed!\n");
		return 1;
	}

	if (VerifyMessage(Setup.srv, dcr_buffer, dcr_size, signature, siglen)) {
		fprintf(stderr, "DoAuthenticateClient : VerifyMessage\n");
		return -1;
	}

	if (EncryptMessageWithPublicKey(Setup.srv, dcr_buffer, dcr_size, cr_buffer, &cr_size)) {
		fprintf(stderr, "DoAuthenticateClient : EncryptMessageWithPublicKey\n");
		return -1;
	}

	if (WriteH(netfd, (struct sockaddr *)srv, cr_buffer, cr_size) < 0) {
		fprintf(stderr, "DoAuthenticateClient : WriteH\n");
		return -1;
	}

	/* Get the connection key and network setup */
	if ((cr_size = ReadN(netfd, (struct sockaddr *)srv, cr_buffer, BUFSIZ)) <= 0) {
		fprintf(stderr, "DoAuthenticateClient : ReadN\n");
		return -1;
	}
	if (DecryptMessageWithPrivateKey(Setup.priv, cr_buffer, cr_size, dcr_buffer, &dcr_size)) {
		fprintf(stdout, "Authentication failed!\n");
		return 1;
	}
	ParseNetworkCapabilities((char *)dcr_buffer);
	CryptoInit(&Setup.ctx, Setup.PrivKey, &Setup.IV);

	return 0;
}

int SendToDestination(int netfd, int tapfd, unsigned char *buffer, int len, ClientConf *Client)
{
	int cr_size = 0, dcr_size = 0;
	unsigned char dcr_buffer[BUFSIZ], cr_buffer[BUFSIZ];

	/* If tapfd == -1, then we get the packet from the "local" and we have to send it to the network, so encrypt it and send it over */
	if (tapfd == -1) {

		/* Encrypt the message with the destination key */
		if (do_encrypt(&(Setup.ctx), Setup.PrivKey, Setup.IV, buffer, len, cr_buffer, &cr_size) < 0) {
			fprintf(stderr, "SendToDestination : do_encrypt\n");
			return -1;
		}

		if (WriteH(netfd, (struct sockaddr *)&Setup.ns.data, cr_buffer, cr_size) < 0) {
		    fprintf(stderr, "SendToDestination : WriteH\n");
		    return -1;
		}
	}

	/* If netfd == -1  then we get the packet from the network and we have to send it to the local, so decrypt it and pass it over */
	else if (netfd == -1) {

		/* Decrypt the message to get the destination */
		if (do_decrypt(&(Setup.ctx), Setup.PrivKey, Setup.IV, buffer, len, dcr_buffer, &dcr_size) < 0) {
			fprintf(stderr, "SendToDestination : do_decrypt\n");
			return -1;
		}

		/* Empty packet. Drop it */
		if (!*dcr_buffer)
			return 0;

		if (write(tapfd, dcr_buffer, dcr_size) < 0) {
			fprintf(stderr, "SendToDestination : write : %s\n", strerror(errno));
			return -1;
		}
	}

	return 0;
}

int DoWorkMultiplexed(int tapfd, int netfd)
{
	int maxfd = 0;
	unsigned char buffer[BUFSIZ];
	size_t len = 0;
	fd_set rd_set;
	struct sockaddr_in from;

	while (1) {

		FD_ZERO(&rd_set);
		FD_SET(tapfd, &rd_set);
		FD_SET(netfd, &rd_set);
		maxfd = (tapfd > netfd) ? tapfd : netfd;
		if (select(maxfd + 1, &rd_set, NULL, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			else {
				fprintf(stderr, "DoWorkMultiplexed : select : %s\n", strerror(errno));
				return -1;
			}
		}

		if (FD_ISSET(tapfd, &rd_set)) {
			if ((len = read(tapfd, buffer, BUFSIZ)) < 0) {
				fprintf(stderr, "DoWorkMultiplexed : read : %s\n", strerror(errno));
				return -1;
			}
			SendToDestination(netfd, -1, buffer, len, NULL);
		}

		else if (FD_ISSET(netfd, &rd_set)) {
			if ((len = ReadN(netfd, (struct sockaddr *)&from, buffer, BUFSIZ)) < 0) {
				fprintf(stderr, "DoWorkMultiplexed : ReadN : %s\n", strerror(errno));
				return -1;
			}
			SendToDestination(-1, tapfd, buffer, len, NULL);
		}
	}
	return 0;
}


int InitializeClient(int tapfd, int sockfd)
{
	int ret = 0;
	struct hostent *he;

	if ((he = gethostbyname(Setup.host)) == NULL) {
		fprintf(stderr, "InitializeClient : gethostbyname : %s\n", strerror(errno));
		return -1;
	}

	memset(&Setup.ns.data, 0, sizeof(struct sockaddr_in));
	memcpy(&Setup.ns.data.sin_addr.s_addr, he->h_addr, he->h_length);
	Setup.ns.data.sin_family = AF_INET;
	Setup.ns.data.sin_port = htons(atoi(Setup.port));

	fprintf(stdout, "Connecting to [%s]...\n", Setup.host);

	if (LoadPrivateKeyFromFile(Setup.fprivkey, &Setup.priv, LOAD_PRIVATE_KEYFILE_ERR("PRIVKEY"))) {
		fprintf(stderr, "InitializeServer : LoadPrivateKeyFromFile\n");
		exit(1);
	}

#if 0
	if (LoadPublicKeyFromFile(Setup.fpubkey, &Setup.pub, LOAD_OWN_PUBLIC_KEYFILE_ERR("PUBKEY"))) {
		fprintf(stderr, "InitializeServer : LoadPublicKeyFromFile\n");
		exit(1);
	}
#endif

	if (LoadPublicKeyFromFile(Setup.fsrvpubkey, &Setup.srv, LOAD_SRV_PUBLIC_KEYFILE_ERR("SRVPUBKEY"))) {
		fprintf(stderr, "InitializeServer : LoadPublicKeyFromFile\n");
		exit(1);
	}

	if ((ret = DoAuthenticateClient(sockfd, &Setup.ns.data)) < 0) {
		fprintf(stderr, "InitializeClient : DoAuthenticateClient\n");
		return -1;
	}

	if (SetInterfaceIP4(sockfd, Setup.ifname, Setup.ns.ip, Setup.ns.brd, Setup.ns.msk, Setup.ns.mtu) < 0) {
		fprintf(stderr, "InitializeClient : SetInterfaceIP4\n");
		return -1;
	}
	inet_aton(Setup.ns.ip, &Setup.ns.data.sin_addr);

	return 0;
}

