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
#include "connection.h"
#include "unix.h"
#include "cfg.h"

#define NTUNNEL "ntunnel"
#define VERSION "0.5"
#define AUTHOR "David B. Cortarello"
#define EMAIL_AUTHOR "dcortarello@gmail.com"

extern ServerConf SrvSetup;

void sayhelp(void)
{
	printf("Usage:\n");
	printf("  %s <Configuration File>\n", NTUNNEL);
	printf("  %s version %s by %s <%s>\n\n", NTUNNEL, VERSION, AUTHOR, EMAIL_AUTHOR);
}

int main(int argc, char *argv[])
{
	int usock = 0, tapfd = 0;

	if (argv[1] == NULL) {
		sayhelp();
		return 1;
	}

	if (!ReadServerSetup(argv[1]))
		return 1;

	if ((tapfd = CreateInterface(SrvSetup.type, SrvSetup.ifname)) < 0)
		return 1;

	if ((usock = CreateMainSocket()) < 0)
		return 1;

	InitializeServer(usock);

	while (1)
		DoWorkMultiplexed(tapfd, usock);

	return 0;
}

