
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
#include <netinet/in.h>
#include "cfg.h"
#include "ini.h"

#define DEFTYPE "tun"
#define DEFIFNAME "vpn"
#define DEFPORT "33333"

#define setdefval(a, str) \
	if (!a) \
		a = strdup(str);

#define rejectnoset(a, b, c) \
	if (!a) { \
		fprintf(stderr, "%s unspecified for [%s]. Rejecting client...\n", b, c); \
		return NULL; \
	}


int CurrentClients;
ServerConf SrvSetup;
ClientConf *Clients;

static int ReadServerHandler(void *config, const char *section, const char *name, const char *value, const char *ms)
{
	ServerConf *pconfig = (ServerConf *)config;

	if (strcmp(section, ms))
		return 1;
	if (!strcasecmp(name, "TYPE"))
		pconfig->type = strdup(value);
	else if (!strcasecmp(name, "IFNAME"))
		pconfig->ifname = strdup(value);
	else if (!strcasecmp(name, "PORT"))
		pconfig->port = strdup(value);
	else if (!strcasecmp(name, "PRIVKEY"))
		pconfig->fprivkey = strdup(value);
	else if (!strcasecmp(name, "PUBKEY"))
		pconfig->fpubkey = strdup(value);
	else if (!strcasecmp(name, "IP"))
		pconfig->ns.ip = strdup(value);

	return 1;
}

static int ReadClientHandler(void *config, const char *section, const char *name, const char *value, const char *ms)
{
	ClientConf *pconfig = (ClientConf *)config;

	if (strcmp(section, ms))
		return 1;

	if (!strcasecmp(name, "IP"))
		pconfig->ns.ip = strdup(value);
	else if (!strcasecmp(name, "NETMASK"))
		pconfig->ns.msk = strdup(value);
	else if (!strcasecmp(name, "BROADCAST"))
		pconfig->ns.brd = strdup(value);
	else if (!strcasecmp(name, "PUBKEY"))
		pconfig->fpubkey = strdup(value);

	return 1;
}

char *ReadServerSetup(const char *cfgfile)
{
	memset(&SrvSetup, '\0', sizeof(ServerConf));
	SrvSetup.cfgfile = strdup(cfgfile);

	if (ini_parse(cfgfile, ReadServerHandler, &SrvSetup, "GLOBAL") < 0) {
		fprintf(stderr, "ReadServerSetup : ini_parse\n");
		return (char *)&SrvSetup;
	}

	setdefval(SrvSetup.type, DEFTYPE);
	setdefval(SrvSetup.ifname, DEFIFNAME);
	setdefval(SrvSetup.port, DEFPORT);

	rejectnoset(SrvSetup.fprivkey, "PRIVKEY", "Server");
	rejectnoset(SrvSetup.ns.ip, "IP", "Server");

	return (char *)&SrvSetup;
}

ClientConf *ReadClientConf(const char *cfgfile, const char *ConnectionID)
{
	ClientConf *Client;

	if (!(Clients = realloc(Clients, sizeof(ClientConf)*(CurrentClients + 1)))) {
		fprintf(stderr, "ReadClientConf : realloc (%s)\n", strerror(errno));
		return NULL;
	}

	Client = Clients + CurrentClients;

	memset(Client, '\0', sizeof(ClientConf));

	if (ini_parse(cfgfile, ReadClientHandler, Client, ConnectionID) < 0) {
		fprintf(stderr, "ReadClientConf : ini_parse\n");
		return NULL;
	}

	setdefval(Client->ConnectionID, ConnectionID);

	rejectnoset(Client->ns.ip, "IP", ConnectionID);
	rejectnoset(Client->ns.msk, "NETMASK", ConnectionID);
	rejectnoset(Client->ns.brd, "BROADCAST", ConnectionID);
	rejectnoset(Client->fpubkey, "PUBKEY", ConnectionID);

	CurrentClients += 1;

	return Client;
}

