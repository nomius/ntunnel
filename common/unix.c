
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_tun.h>

#define NSECS_AUTH 5

const char *clonedev = "/dev/net/tun";
#ifdef SUPER_SECURITY
const char *randomdev = "/dev/random";
#else
const char *randomdev = "/dev/urandom";
#endif

void debug(char *prefix, void *data, size_t data_len)
{
#if DEBUG
	register int i = 0;

	fprintf(stdout, "%s (lenght %.4d): ", prefix, (int)data_len);
	for (i=0; i < data_len; i++)
		fprintf(stdout, "0x%2.2X ", ((unsigned char *)data)[i]);
	printf("\n\n");
#endif
}

int ReadN(int fd, struct sockaddr *fromwhere, unsigned char *buf, size_t n)
{
	uint32_t plength = 0;
	fd_set rd_set;
	struct timeval tv;
	int nread = 0, left = 0, t = 0;
	socklen_t addrlen = sizeof(struct sockaddr);

	/* Read the incoming packet size */
	if ((nread = recvfrom(fd, &plength, sizeof(plength), 0, fromwhere, &addrlen)) < sizeof(plength))
		return (nread == 0 ? 0 : nread);

	debug("Data read [header]", &plength, sizeof(plength));
	/* Transform the network packet size endianess to host endianess */
	if ((left = ntohl(plength)) > n) {
		fprintf(stderr, "JUMBO PACKET NOT SUPPORTED DUE TO ENCRYPTION!!!!!\n");
		return -1;
	}

	while (left > 0) {

		/* Poll it damn it! */
		FD_ZERO(&rd_set);
		FD_SET(fd, &rd_set);
		tv.tv_sec = NSECS_AUTH;
		tv.tv_usec = 0;
		switch (select(fd + 1, &rd_set, NULL, NULL, &tv)) {

			/* Ooops, error. Drop it! */
			case -1:
				fprintf(stderr, "ReadN : select : %s\n", strerror(errno));
				return -1;
				
			case 0:
				/* UDP empty packet, means only header */
				return 0;

			default:
				if (FD_ISSET(fd, &rd_set)) {

					/* There's something to be read in the socket */
					switch ((nread = recvfrom(fd, buf, left, 0, (struct sockaddr *)fromwhere, &addrlen))) {
						case 0:
							return 0;
						case -1:
							fprintf(stderr, "ReadN : read : %s\n", strerror(errno));
							return -1;
						default:
							debug("Data read", buf, nread);
							left -= nread;
							buf += nread;
							t += nread;
					}
				}
				break;
		}
		usleep(1);
	}

	return t;
}

int WriteH(int fd, struct sockaddr *towhere, void *buf, size_t len)
{
	uint32_t plength = 0;
	int nwrite = 0, left = len;
	socklen_t addrlen = sizeof(struct sockaddr);

	/* Transform the host endianess to network packet size endianess and send it to the destination */
	plength = htonl(len);
	if ((nwrite = sendto(fd, &plength, sizeof(plength), 0, towhere, addrlen)) < 0) {
		fprintf(stderr, "WriteH : sendto : %s\n", strerror(errno));
		return -1;
	}
	debug("Data sent [header]", &plength, sizeof(plength));

	/* Send the full chunk */
	while (left > 0)
		switch ((nwrite = sendto(fd, buf, left, 0, towhere, addrlen))) {
			case 0:
				return 0;
			case -1:
				fprintf(stderr, "WriteH : sendto : %s\n", strerror(errno));
				return -1;
			default:
				debug("Data sent", buf, nwrite);
				left -= nwrite;
				buf = ((char *)buf) + nwrite;
		}
	return len;
}


int CreateInterface(char *type, char *ifname)
{
	int fd, flags = IFF_NO_PI;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));

	if (!strcasecmp(type, "tap"))
		flags |= IFF_TAP;
	else
		flags |= IFF_TUN;

	ifr.ifr_flags = flags;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if ((fd = open(clonedev, O_RDWR)) < 0) {
		fprintf(stderr, "CreateInterface : open : %s\n", strerror(errno));
		return -1;
	}

	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
		fprintf(stderr, "CreateInterface : ioctl : %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

int SetInterfaceIP4(int sockfd, char *ifname, char *ip, char *broadcast, char *netmask, char *mtu)
{
	struct ifreq ifr;
	struct sockaddr_in sin;

	memset(&sin, 0, sizeof(struct sockaddr));
	sin.sin_family = AF_INET;
	sin.sin_port = 0;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "SetInterfaceIP4 : ioctl(SIOCGIFFLAGS) : %s\n", strerror(errno));
		return -1;
	}

	if (ifr.ifr_flags | ~(IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
			fprintf(stderr, "SetInterfaceIP4 : ioctl(SIOCSIFFLAGS) : %s\n", strerror(errno));
			return -1;
		}
	}

	inet_aton(ip, &sin.sin_addr);
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));

	if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
		fprintf(stderr, "SetInterfaceIP4 : ioctl(SIOCSIFADDR) : %s\n", strerror(errno));
		return -1;
	}

	/*inet_aton(ptpaddr, &sin.sin_addr);
	memcpy(&ifr.ifr_dstaddr, &sin, sizeof(struct sockaddr));

	if (ioctl(sockfd, SIOCSIFDSTADDR, &ifr) < 0) {
		fprintf(stderr, "SetInterfaceIP4 : ioctl (SIOCSIFDSTADDR) : %s\n", strerror(errno));
		return -1;
	}*/

	return 0;
}

int CreateRandomKey(unsigned char *key, int len)
{
	int frandom = -1;
	register int i = 0;

	if ((frandom = open(randomdev, O_RDONLY)) < 0) {
		fprintf(stderr, "CreateRandomKey : open : %s\n", strerror(errno));
		return -1;
	}

	while ((i += read(frandom, key+i, len-i)) < len) ;

	if (i < 0) {
		fprintf(stderr, "CreateRandomKey : read : %s\n", strerror(errno));
		return -1;
	}

#ifdef DEBUG
	fprintf(stdout, "Key created: ");
	for (i = 0; i < len; i++)
		fprintf(stdout, "0x%2.2X ", key[i]);
	fprintf(stdout, "\n");
#endif

	close(frandom);
	return 0;
}

int CreateMainSocket(void)
{
	int sockfd = 0;

	/* Create the udp socket */
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "CreateMainSocket : socket : %s\n", strerror(errno));
		return -1;
	}

	return sockfd;
}
