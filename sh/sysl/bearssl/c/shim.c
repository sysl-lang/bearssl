/*
 * The part of BearSSL's interface that only C can reach: functions `bearssl_*.h` defines `static
 * inline`, which have no symbol to link against. Each wrapper here is the inline function's body
 * called once, and nothing else; the declarations in `c.sysl` name these instead.
 */

#include "bearssl.h"

int sysl_br_engine_last_error(const br_ssl_engine_context *cc)
{
	return br_ssl_engine_last_error(cc);
}

void sysl_br_engine_set_versions(br_ssl_engine_context *cc, unsigned lo, unsigned hi)
{
	br_ssl_engine_set_versions(cc, lo, hi);
}

unsigned sysl_br_engine_version(const br_ssl_engine_context *cc)
{
	return br_ssl_engine_get_version(cc);
}

unsigned sysl_br_engine_cipher_suite(const br_ssl_engine_context *cc)
{
	br_ssl_session_parameters pp;

	br_ssl_engine_get_session_parameters(cc, &pp);
	return pp.cipher_suite;
}

void sysl_br_x509_minimal_set_time(br_x509_minimal_context *ctx, uint32_t days, uint32_t seconds)
{
	br_x509_minimal_set_time(ctx, days, seconds);
}

void sysl_br_pem_decoder_setdest(br_pem_decoder_context *ctx,
	void (*dest)(void *dest_ctx, const void *src, size_t len), void *dest_ctx)
{
	br_pem_decoder_setdest(ctx, dest, dest_ctx);
}

const char *sysl_br_pem_decoder_name(br_pem_decoder_context *ctx)
{
	return br_pem_decoder_name(ctx);
}

const br_x509_pkey *sysl_br_x509_decoder_get_pkey(br_x509_decoder_context *ctx)
{
	return br_x509_decoder_get_pkey(ctx);
}

int sysl_br_x509_decoder_last_error(br_x509_decoder_context *ctx)
{
	return br_x509_decoder_last_error(ctx);
}

int sysl_br_x509_decoder_is_ca(br_x509_decoder_context *ctx)
{
	return br_x509_decoder_isCA(ctx);
}

int sysl_br_x509_decoder_signer_key_type(br_x509_decoder_context *ctx)
{
	return br_x509_decoder_get_signer_key_type(ctx);
}

int sysl_br_skey_decoder_last_error(const br_skey_decoder_context *ctx)
{
	return br_skey_decoder_last_error(ctx);
}

int sysl_br_skey_decoder_key_type(const br_skey_decoder_context *ctx)
{
	return br_skey_decoder_key_type(ctx);
}

const br_rsa_private_key *sysl_br_skey_decoder_get_rsa(const br_skey_decoder_context *ctx)
{
	return br_skey_decoder_get_rsa(ctx);
}

const br_ec_private_key *sysl_br_skey_decoder_get_ec(const br_skey_decoder_context *ctx)
{
	return br_skey_decoder_get_ec(ctx);
}
