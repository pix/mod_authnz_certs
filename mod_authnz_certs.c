/* ====================================================================
 * Copyright (c) 1995 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * IT'S CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */


/* Uncomment if you want to use a HARDCODE'd check (default off) */
/* #define _HARDCODE_ */

#ifdef _HARDCODE_
  /* Uncomment if you want to use your own Hardcode (default off) */
  /*             MUST HAVE _HARDCODE_ defined above!                */
  /* #include "your_function_here.c" */
#endif


#include "apr_lib.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "mod_auth.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_optional.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/
#include "mod_ssl.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef STANDARD20_MODULE_STUFF
#error This module requires Apache 2.2.0 or later.
#endif

/* Names of environment variables used to pass data to authenticator */
#define ENV_CLIENT_VERIFY "SSL_CLIENT_VERIFY"

/*
 * Structure for the module itself.  The actual definition of this structure
 * is at the end of the file.
 */
static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *ptr_ssl_lookup = NULL;
module AP_MODULE_DECLARE_DATA authnz_certs_module;

/*
 *  Data types for per-directory and per-server configuration
 */

typedef struct
{
    int    authoritative;                 /* Are we authoritative in current dir? */
    char*  ssl_username;
} authnz_certs_dir_config_rec;

/*
 * Creators for per-dir and server configurations.  These are called
 * via the hooks in the module declaration to allocate and initialize
 * the per-directory and per-server configuration data structures declared
 * above.
 */
static void *create_authnz_certs_dir_config(apr_pool_t *p, char *d)
{
    ptr_ssl_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);

    authnz_certs_dir_config_rec *dir= (authnz_certs_dir_config_rec *)
        apr_palloc(p, sizeof(authnz_certs_dir_config_rec));

    dir->authoritative= 1;        /* strong by default */
    dir->ssl_username = NULL;
    return dir;
}

/*
 * Config file commands that this module can handle
 */
static const command_rec authnz_certs_cmds[] =
{
    AP_INIT_FLAG("CertsAuthoritative",
        ap_set_flag_slot,
        (void *)APR_OFFSETOF(authnz_certs_dir_config_rec, authoritative),
        OR_AUTHCFG,
        "Are certificates authoritative" ),
    AP_INIT_TAKE1("CertsSSLUsernameOverride",
        ap_set_string_slot,
	(void *)APR_OFFSETOF(authnz_certs_dir_config_rec, ssl_username),
	OR_AUTHCFG,
	"Override username (REMOTE_USER) with a field fetched from mod_ssl"),
    { NULL }
};

/* Password checker for basic authentication - given a login/password,
 * check if it is valid.  Returns one of AUTH_DENIED, AUTH_GRANTED,
 * or AUTH_GENERAL_ERROR.
 */
static authn_status authn_certs_check_password(request_rec *r, const char *user, 
        const char *password)
{
    authnz_certs_dir_config_rec *dir= (authnz_certs_dir_config_rec *)
            ap_get_module_config(r->per_dir_config, &authnz_certs_module);


    if (ptr_ssl_lookup) {
        const char *ssl_client_verify = ptr_ssl_lookup(r->pool, r->server, r->connection, (request_rec *)r, ENV_CLIENT_VERIFY);

        if (ssl_client_verify && strcmp(ssl_client_verify, "SUCCESS") == 0){
	    if(dir->ssl_username != NULL){
	    	const char * username = ptr_ssl_lookup(r->pool, r->server, 
			r->connection, (request_rec *)r, dir->ssl_username);
		if(username){
            		r->user = apr_pstrdup(r->pool, username);
		}else{
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"AuthCerts: Unable to set fetch the username from mod_ssl. Typo ?");
		}
	    }

            // Seems like a valid user, needz more checks.
            return AUTH_GRANTED;
        }else{
            // Client isn't verified
            return AUTH_DENIED;
        }
    }else{
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "AuthCerts: Unable to retrieve ptr_ssl_lookup, is mod_ssl loaded ?");
        return AUTH_DENIED;
    }

    // How did we get here !?
    return AUTH_DENIED;
}


static int authz_certs_check_user_access(request_rec *r)
{
    authnz_certs_dir_config_rec *dir= (authnz_certs_dir_config_rec *)
            ap_get_module_config(r->per_dir_config, &authnz_certs_module);

    if (!dir->authoritative) {
        return DECLINED;
    }

    ap_note_basic_auth_failure (r);
    return HTTP_UNAUTHORIZED;

}

static const authn_provider authn_certs_provider =
{
    &authn_certs_check_password,
    NULL                /* No support for digest authentication at this time */
};


static void register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "certs", "0",
            &authn_certs_provider);

    ap_hook_auth_checker(authz_certs_check_user_access, NULL, NULL,
            APR_HOOK_LAST);

}


module AP_MODULE_DECLARE_DATA authnz_certs_module = {
    STANDARD20_MODULE_STUFF,
    create_authnz_certs_dir_config,          /* create per-dir config */
    NULL,                          /* merge per-dir config - dflt is override */
    NULL,                         /* create per-server config */
    NULL,                          /* merge per-server config */
    authnz_certs_cmds,          /* command apr_table_t */
    register_hooks                  /* register hooks */
};
