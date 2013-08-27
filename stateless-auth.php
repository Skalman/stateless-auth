<?php
/* Copyright 2013 Dan Wolff (danwolff.se)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/**
 * Creates a token that the server can authenticate. This is completely
 * stateless, and all necessary information is stored inside the token.
 * This means that once a token is created, it can only be invalidated
 * by expiring.
 */
function stateless_auth_create($secret_key, $context, $time = 60) {
	$expiry_time = time() + $time;
	// Use HMAC to prevent length extension attacks
	$hash = hash_hmac('sha256', "$expiry_time:$context", $secret_key, true);
	// It will only be decoded by this library, so strip extra '='
	$encoded_hash = rtrim(base64_encode($hash), '=');
	// $context may contain ':', so place it last
	return "$encoded_hash:$expiry_time:$context";
}

/**
 * Checks whether a token is valid. If it is misformatted, the expiry
 * time has passed, or the token is valid only for another context, it
 * is considered invalid.
 */
function stateless_auth_verify($secret_key, $context, $token) {
	if (!is_string($token)) {
		return false;
	}
	$token_parts = explode(':', $token, 3);
	if (count($token_parts) !== 3) {
		// misformatted token
		return false;
	}
	list($token_encoded_hash, $token_expiry_time, $token_context) = $token_parts;

	if (!is_numeric($token_expiry_time) || $token_expiry_time < time()) {
		// already expired (or incorrect expiry time given)
		return false;
	}
	if ($token_context !== (string) $context) {
		// context mismatch
		return false;
	}

	$token_hash = base64_decode($token_encoded_hash, true);
	$calculated_hash = hash_hmac('sha256', "$token_expiry_time:$context", $secret_key, true);

	return $token_hash === $calculated_hash;
}

/**
 * Gets the expiry time for a given token. False is returned if it
 * cannot be extracted.
 */
function stateless_auth_get_expiry($token) {
	$parts = explode(':', $token, 3);
	if (count($parts) !== 3) {
		// misformatted token
		return false;
	}
	$expiry_time = $parts[1];
	if (!is_numeric($expiry_time)) {
		return false;
	}
	return +$expiry_time;
}

/**
 * Gets the context for a given token. False is returned if it cannot
 * be extracted.
 */
function stateless_auth_get_context($token) {
	$parts = explode(':', $token, 3);
	if (count($parts) !== 3) {
		// misformatted token
		return false;
	}
	return $parts[2];
}
