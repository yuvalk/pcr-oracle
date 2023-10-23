/*
 *   Copyright (C) 2022, 2023 SUSE LLC
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Written by Olaf Kirch <okir@suse.com>
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <ctype.h>

#include <tss2_esys.h>
#include <tss2_sys.h>
#include <tss2_tctildr.h>
#include <tss2_rc.h>
#include <tss2_mu.h>

#include "oracle.h"
#include "tpm.h"
#include "util.h"
#include "config.h"

uint32_t	esys_tr_rh_null = ~0;
uint32_t	esys_tr_rh_owner = ~0;

void
tss_print_error(int rc, const char *msg)
{
	const char *tss_msg;

	if (rc == TSS2_RC_SUCCESS)
		return;

	tss_msg = Tss2_RC_Decode(rc);
	if (tss_msg == NULL)
		tss_msg = "Unknown error code";

	if (msg)
		error("%s: %s\n", msg, tss_msg);
	else
		error("tss2 function returned an error: %s\n", tss_msg);
}


ESYS_CONTEXT *
tss_esys_context(void)
{
	static ESYS_CONTEXT  *esys_ctx;

	if (esys_ctx == NULL) {
		TSS2_RC rc;

		rc = Esys_Initialize(&esys_ctx, NULL, NULL);
		if (!tss_check_error(rc, "Unable to initialize TSS2 ESAPI context"))
			fatal("Aborting.\n");

		/* There's no way to query the library version programmatically, so
		 * we need to check it in configure. */
		if (version_string_compare(LIBTSS2_VERSION, "3.1") > 0) {
			/* debug("Detected tss2-esys library version %s, using new ESYS_TR_RH_* constants\n", LIBTSS2_VERSION); */
			esys_tr_rh_null = ESYS_TR_RH_NULL;
			esys_tr_rh_owner = ESYS_TR_RH_OWNER;
		} else {
			debug("Detected tss2-esys library version %s, using old TPM2_RH_* constants\n", LIBTSS2_VERSION);
			esys_tr_rh_null = TPM2_RH_NULL;
			esys_tr_rh_owner = TPM2_RH_OWNER;
		}
	}
	return esys_ctx;
}

bool
tpm_selftest(bool fulltest)
{
	ESYS_CONTEXT *esys_ctx = tss_esys_context();
	TSS2_RC rc;

	rc = Esys_SelfTest(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, fulltest);
	return tss_check_error(rc, "TPM self test failed");
}

bool
tpm_rsa_bits_test(unsigned int rsa_bits)
{
	ESYS_CONTEXT *esys_ctx = tss_esys_context();
	TPMT_PUBLIC_PARMS rsa_parms = {
		.type = TPM2_ALG_RSA,
		.parameters = {
			.rsaDetail = {
				.symmetric = { TPM2_ALG_NULL },
				.scheme = { TPM2_ALG_NULL },
				.keyBits = rsa_bits
			}
		}
	};
	TSS2_RC rc;
	bool okay = false;

	/* Suppress the messages from tpm2-tss */
	setenv("TSS2_LOG", "all+NONE", 1);

	rc = Esys_TestParms(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
			ESYS_TR_NONE, &rsa_parms);
	if (rc == TSS2_RC_SUCCESS)
		okay = true;
	else if (rc != (TPM2_RC_VALUE | TPM2_RC_P | TPM2_RC_1)) {
		tss_check_error(rc, "Esys_CreatePrimary failed");
	}

	return okay;
}
