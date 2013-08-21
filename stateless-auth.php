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
 *
 * @param string $secret_key
 *   A secret value that the server keeps - the security of the token
 *   relies on an attacker not knowing this. It should be generated to
 *   have at least 128 bits of entropy.
 * @param string $context
 *   In which context should the token be valid? Be as specific as
 *   possible: if it is used to prevent XSRF, include both the username
 *   and the form where it is to be used. If it is used for login,
 *   include both the username and something indicating 'login'. The
 *   more specific this is, the lower the chance that a token will be
 *   used in the wrong situation.
 * @param number $time = 60
 *   The time for which the generated token will be valid (in seconds).
 *   Be careful to not set this too high: tokens cannot easily be
 *   cancelled.
 * @return string
 *   Returns the token as a string. The string contains a hash, the
 *   token's expiry time and $context.
 */
function stateless_auth_sign($secret_key, $context, $time = 60) {
	$expiry_time = time() + $time;
	$hash = hash_hmac('sha256', "$expiry_time:$context", $secret_key, true);
	$encoded_hash = rtrim(base64_encode($hash), '=');
	return "$encoded_hash:$expiry_time:$context";
}

/**
 * Checks whether a token is valid. If it is misformatted, the expiry
 * time has passed, or the token is valid only for another context, it
 * is considered invalid.
 * @param string $token
 *   The token to check.
 * @param string $secret_key
 *   The same secret that was used to create the token.
 * @param string $context
 *   The context that was given when creating the token.
 * @return boolean
 *   Returns true if the given token is valid for the given context,
 *   otherwise false.
 */
function stateless_auth_verify($token, $secret_key, $context) {
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
 * Gets the expiry time for a given token.
 * @param string $token
 *   The token to get the expiry time for.
 * @return number or false
 *   Returns the expiry time in number of seconds since the Unix epoch.
 *   If the token is so badly formatted that it is impossible to
 *   extract the expiry time, false is returned.
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
 * Gets the expiry time for a given token.
 * @param string $token
 *   The token to get the expiry time for.
 * @return string or false
 *   Returns the context for the given token. If the token is so badly
 *   formatted that it is impossible to extract the context, false is
 *   returned.
 */
function stateless_auth_get_context($token) {
	$parts = explode(':', $token, 3);
	if (count($parts) !== 3) {
		// misformatted token
		return false;
	}
	return $parts[2];
}
