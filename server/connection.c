
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
#include <linux/ip.h>
#include <errno.h>
#include <openssl/evp.h>
#include "cfg.h"
#include "unix.h"
#include "rsa.h"
#include "blowfish.h"

#define MIN_BUF 16
#define MED_BUF 128

#define LOAD_OWN_PUBLIC_KEYFILE_ERR(x) x" not set. You can create it from the private key with:\n" \
                                        " openssl rsa -in PRIVATE_KEY.pem -pubout > PUBLIC_KEY.pem\n"

#define LOAD_PRIVATE_KEYFILE_ERR(x) x" not set. You can create a KeyPair with:\n" \
                                     " openssl genrsa -out PRIVATE_KEY.pem 1024\n" \
                                     " openssl rsa -in PRIVATE_KEY.pem -pubout > PUBLIC_KEY.pem\n"
#define CLIENT_LOAD_SERVER_PUBLIC_KEYFILE_ERR "Can't load client's public key."

extern int CurrentClients;
extern ServerConf SrvSetup;
extern ClientConf *Clients;

int SendToDestination(int netfd, int tapfd, unsigned char *buffer, int len, ClientConf *Client)
{
	int cr_size = 0, dcr_size = 0;
	unsigned char dcr_buffer[BUFSIZ], cr_buffer[BUFSIZ];
	register int i = 0;
	struct iphdr *header;
	struct in_addr dst;

	/* If Client == NULL, then the packet is a raw packet from the tun/tap device, so it must not be decrypted */
	if (Client != NULL) {

		if (len == 0)
			return 0;

		/* Decrypt the message to get the destination */
		if (do_decrypt(&(Client->ctx), Client->PrivKey, Client->IV, buffer, len, dcr_buffer, &dcr_size) < 0) {
			fprintf(stderr, "SendToDestination : do_decrypt\n");
			return -1;
		}

		/* Empty packet. Drop it */
		if (!*dcr_buffer)
			return 0;
	}

	/* Get the header and the destination address */
	header = (Client == NULL ? (struct iphdr *)buffer : (struct iphdr *)dcr_buffer);
	dst.s_addr = header->daddr;

	/* Get the destination client's information if we have it */
	for (i = 0; i < CurrentClients; i++)
		if (dst.s_addr == Clients[i].ns.data.sin_addr.s_addr)
			Client = Clients + i;

	if (Client != NULL) {
		printf("SENT!\n");
		/* Encrypt the message with the destination key */
		if (do_encrypt(&(Client->ctx), Client->PrivKey, Client->IV, dcr_buffer, dcr_size, cr_buffer, &cr_size) < 0) {
			fprintf(stderr, "SendToDestination : do_encrypt\n");
			return -1;
		}
	}
	else
		return 0;

	if (WriteH(netfd, (struct sockaddr *)&Client->ns.data, (Client != NULL) ? cr_buffer : dcr_buffer, (Client != NULL) ? cr_size : dcr_size) < 0) {
	    fprintf(stderr, "SendToDestination : WriteH\n");
	    return -1;
	}

	return 0;
}

ClientConf *DoAuthenticateServer(int net_fd, struct sockaddr_in *from)
{
	ClientConf *Client = NULL;
	int dcr_size = 0, cr_size = 0, i = 0;
	char ConnectionID[MED_BUF];
	unsigned char cr_buffer[BUFSIZ], dcr_buffer[BUFSIZ], orig_buffer[BUFSIZ], signature[MED_BUF];
	unsigned int siglen = 0;

	memset(dcr_buffer, 0, sizeof(dcr_buffer));
	memset(orig_buffer, 0, sizeof(orig_buffer));

	/* Get the connection ID */
	if ((i = ReadN(net_fd, (struct sockaddr *)from, (unsigned char *)ConnectionID, MED_BUF)) <= 0) {
		fprintf(stderr, "DoAuthenticateServer : ReadN\n");
		return NULL;
	}
	ConnectionID[i] = '\0';

	/* Load the client setup */
	if ((Client = ReadClientConf(SrvSetup.cfgfile, ConnectionID)) == NULL) {
		fprintf(stderr, "DoAuthenticateServer : ReadClientConf\n");
		return NULL;
	}
	if (LoadPublicKeyFromFile(Client->fpubkey, &(Client->pub), CLIENT_LOAD_SERVER_PUBLIC_KEYFILE_ERR)) {
		fprintf(stderr, "DoAuthenticateServer : LoadPublicKeyFromFile\n");
		return NULL;
	}

	/* Create a random message, sign it, encrypt it and send it with its signature */
	if (CreateRandomMessage(orig_buffer, MIN_BUF) < 0) {
		fprintf(stderr, "DoAuthenticateServer : CreateRandomMessage\n");
		return NULL;
	}
	if (SignMessage(SrvSetup.priv, orig_buffer, MIN_BUF, signature, &siglen) < 0) {
		fprintf(stderr, "DoAuthenticateServer : SignMesage\n");
		return NULL;
	}
	if (EncryptMessageWithPublicKey(Client->pub, orig_buffer, MIN_BUF, cr_buffer, &cr_size) < 0) {
		fprintf(stderr, "DoAuthenticateServer : EncryptMessageWithPublicKey\n");
		return NULL;
	}
	if (WriteH(net_fd, (struct sockaddr *)from, cr_buffer, cr_size) < 0) {
		fprintf(stderr, "DoAuthenticateServer : WriteH\n");
		return NULL;
	}
	if (WriteH(net_fd, (struct sockaddr *)from, signature, siglen) <= 0) {
		fprintf(stderr, "DoAuthenticateServer : WriteH\n");
		return NULL;
	}

	/* Read the answer and decrypt it */
	if ((cr_size = ReadN(net_fd, (struct sockaddr *)from, cr_buffer, BUFSIZ)) < 0) {
		fprintf(stderr, "DoAuthenticateServer : ReadN\n");
		return NULL;
	}
	else if (cr_size == 0) {
		fprintf(stderr, "Authentication failed. Access denied!\n");
		fprintf(stderr, "Disconnecting client\n");
		return NULL;
	}
	if (DecryptMessageWithPrivateKey(SrvSetup.priv, cr_buffer, cr_size, dcr_buffer, &dcr_size)) {
		fprintf(stderr, "DoAuthenticateServer : DecryptMessageWithPrivateKey\n");
		return NULL;
	}

	/* Check if the message is ok */
	if (memcmp(orig_buffer, dcr_buffer, MIN_BUF)) {
		fprintf(stderr, "Access denied!\n");
		return NULL;
	}

	/* Save the origin information in the client's structure */
	memcpy(&(Client->ns.data), from, sizeof(struct sockaddr_in));
	inet_aton(Client->ns.ip, &Client->ns.data.sin_addr);

	/* Create a key, arrange a network setup for the client and send it over */
	if (CreateRandomKey(Client->PrivKey, KEYSIZE)) {
		fprintf(stderr, "DoAuthenticateServer : CreateRandomKey\n");
		return NULL;
	}
	/*sprintf((char *)dcr_buffer, "key=%s,ip=%s,netmask=%s,broadcast=%s,mtu=%s", Client->PrivKey, Client->ns.ip, Client->ns.msk, Client->ns.brd, Client->ns.mtu);*/

	memset(dcr_buffer, '\0', sizeof(dcr_buffer));
	memcpy(dcr_buffer, "key=", 4);
	memcpy(dcr_buffer + 4, Client->PrivKey, KEYSIZE);
	sprintf((char *)dcr_buffer + 4 + KEYSIZE, ",ip=%s,netmask=%s,broadcast=%s", Client->ns.ip, Client->ns.msk, Client->ns.brd);
	dcr_size = 4 + KEYSIZE + strlen(((char *)dcr_buffer) + 4 + KEYSIZE);

	if (EncryptMessageWithPublicKey(Client->pub, dcr_buffer, dcr_size, cr_buffer, &cr_size) < 0) {
		fprintf(stderr, "DoAuthenticateServer : EncryptMessageWithPublicKey\n");
		return NULL;
	}
	if (WriteH(net_fd, (struct sockaddr *)from, cr_buffer, cr_size) < 0) {
		fprintf(stderr, "DoAuthenticateServer : WriteH\n");
		return NULL;
	}

	CryptoInit(&(Client->ctx), Client->PrivKey, &(Client->IV));

	return Client;
}


int DoWorkMultiplexed(int tapfd, int netfd)
{
	int maxfd = 0;
	register int i = 0;
	unsigned char buffer[BUFSIZ];
   	char ip4[INET_ADDRSTRLEN];
	size_t len = 0;
	fd_set rd_set;
	struct sockaddr_in from;
	ClientConf *Client;

	maxfd = (tapfd > netfd) ? tapfd : netfd;

	while (1) {

		Client = NULL;
		FD_ZERO(&rd_set);
		FD_SET(tapfd, &rd_set);
		FD_SET(netfd, &rd_set);
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
			printf("read from the tuntap [%d]\n", (int)len);

			SendToDestination(netfd, tapfd, buffer, len, NULL);
		}

		else if (FD_ISSET(netfd, &rd_set)) {
			printf("read from the network\n");
			if ((len = ReadN(netfd, (struct sockaddr *)&from, buffer, BUFSIZ)) < 0) {
				fprintf(stderr, "DoWorkMultiplexed : ReadN : %s\n", strerror(errno));
				return -1;
			}

			/* Get the source client's information */
			for (i = 0; i < CurrentClients; i++)
				if (from.sin_addr.s_addr == Clients[i].ns.data.sin_addr.s_addr) {
					Client = Clients + i;
					printf("found: %s\n", Client->ns.ip);
				}

			/* If we have no client information, then try to authenticate it */
			if (!Client) {
				if (!(Client = DoAuthenticateServer(netfd, &from))) {
					inet_ntop(AF_INET, &(from.sin_addr), ip4, INET_ADDRSTRLEN);
					fprintf(stdout, "Client [%s] rejected. Wrong credentials\n", ip4);
				}
				continue;
			}

			SendToDestination(netfd, tapfd, buffer, len, Client);
		}
	}
	return 0;
}

int InitializeServer(int sockfd)
{
	memset(&SrvSetup.ns.data, 0, sizeof(struct sockaddr_in));
	SrvSetup.ns.data.sin_family = AF_INET;
	SrvSetup.ns.data.sin_addr.s_addr = htonl(INADDR_ANY);
	SrvSetup.ns.data.sin_port = htons(atoi(SrvSetup.port));

	if (bind(sockfd, (struct sockaddr *)&SrvSetup.ns.data, sizeof(struct sockaddr_in)) < 0) {
		fprintf(stderr, "InitializeServer : bind : %s\n", strerror(errno));
		return -1;
	}

	if (LoadPrivateKeyFromFile(SrvSetup.fprivkey, &SrvSetup.priv, LOAD_PRIVATE_KEYFILE_ERR("PRIVKEY"))) {
		fprintf(stderr, "InitializeServer : LoadPrivateKeyFromFile\n");
		exit(1);
	}

#if 0
	if (LoadPublicKeyFromFile(SrvSetup.fpubkey, &SrvSetup.pub, LOAD_OWN_PUBLIC_KEYFILE_ERR("PUBKEY"))) {
		fprintf(stderr, "InitializeServer : LoadPublicKeyFromFile\n");
		exit(1);
	}
#endif

	if (SetInterfaceIP4(sockfd, SrvSetup.ifname, SrvSetup.ns.ip, SrvSetup.ns.brd, SrvSetup.ns.msk, "1500") < 0) {
		fprintf(stderr, "InitializeServer : SetInterfaceIP4\n");
		exit(1);
	}

	CurrentClients = 0;
	Clients = NULL;

	return 0;
}
