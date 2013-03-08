/*
 * AES SIV (RFC5297)
 *
 * Copyright (c) 2013 Cozybit, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

int aes_siv_encrypt(const u8 *key, const u8 *pw,
		    size_t pwlen, size_t num_elem,
		    const u8 *addr[], const size_t *len, u8 *out);
int aes_siv_decrypt(const u8 *key, const u8 *iv_crypt, size_t iv_c_len,
		    int num_elem, const u8 *addr[], const size_t *len,
		    u8 *out);
