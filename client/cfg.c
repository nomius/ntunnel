
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "cfg.h"
#include "ini.h"

#define DEFTYPE "tun"
#define DEFIFNAME "vpn"
#define DEFPORT "33333"

#define MATCH(s, n) (!strcasecmp(section, s) && !strcasecmp(name, n))

#define setdefval(a, str) \
	if (!a) \
		a = strdup(str);


#define rejectnoset(a, b, c) \
	if (!a) { \
		fprintf(stderr, "%s unspecified for [%s]. Leaving...\n", b, c); \
		return 1; \
	}

ClientConf Setup;

static int ReadClientHandler(void *config, const char *section, const char *name, const char *value, const char *ms)
{
	ClientConf *pconfig = (ClientConf *)config;

	if (MATCH(ms, "TYPE"))
		pconfig->type = strdup(value);
	else if (MATCH(ms, "IFNAME"))
		pconfig->ifname = strdup(value);
	else if (MATCH(ms, "PORT"))
		pconfig->port = strdup(value);
	else if (MATCH(ms, "PRIVKEY"))
		pconfig->fprivkey = strdup(value);
	else if (MATCH(ms, "PUBKEY"))
		pconfig->fpubkey = strdup(value);
	else if (MATCH(ms, "SRVPUBKEY"))
		pconfig->fsrvpubkey = strdup(value);
	else if (MATCH(ms, "HOST"))
		pconfig->host = strdup(value);

	return 1;
}


int ReadClientSetup(const char *cfgfile, char *ConnectionID)
{
	memset(&Setup, '\0', sizeof(ClientConf));

	Setup.cfgfile = strdup(cfgfile);
	Setup.ConnectionID = strdup(ConnectionID);

	if (ini_parse(cfgfile, ReadClientHandler, &Setup, ConnectionID) < 0) {
		fprintf(stderr, "ReadClientSetup : ini_parse\n");
		return -1;
	}

	setdefval(Setup.type, DEFTYPE);
	setdefval(Setup.ifname, DEFIFNAME);
	setdefval(Setup.port, DEFPORT);

	rejectnoset(Setup.host, "HOST", ConnectionID);
	rejectnoset(Setup.fprivkey, "PRIVKEY", ConnectionID);
	/*rejectnoset(Setup.fpubkey, "PUBKEY", ConnectionID);*/
	rejectnoset(Setup.fsrvpubkey, "SRVPUBKEY", ConnectionID);

	return 0;
}

static char *colondup(char *str)
{
	int i = 0;
	char *ptr = NULL;

	while (*(str+i) != ',' && *(str+i) != '\n' && *(str+i) != '\0')
		i++;

	if (!(ptr = malloc(sizeof(char)*(i+1))))
		return NULL;

	memcpy(ptr, str, i);
	*(ptr+i) = '\0';
	return ptr;
}

void ParseNetworkCapabilities(char *str)
{
	char *ptr = NULL;

	if ((ptr = strstr(str, "key=")))
		memcpy(Setup.PrivKey, ptr + 4, KEYSIZE);
	str += 4 + KEYSIZE;
	if ((ptr = strstr(str, "ip=")))
		Setup.ns.ip = colondup(ptr + 3);
	if ((ptr = strstr(str, "netmask=")))
		Setup.ns.msk = colondup(ptr + 8);
	if ((ptr = strstr(str, "broadcast=")))
		Setup.ns.brd = colondup(ptr + 10);
	
	printf("%s : %s : %s\n", Setup.ns.ip, Setup.ns.msk, Setup.ns.brd);

	inet_aton(Setup.ns.ip, &Setup.ns.data.sin_addr);
}

