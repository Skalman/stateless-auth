<?php
/* Copyright 2013 Dan Wolff (danwolff.se)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

require 'stateless-auth.php';

class Stateless_auth_test extends PHPUnit_Framework_TestCase {
	public function test_sign() {
		$token = stateless_auth_sign('secret key', 'login:username', 60);

		$this->assertInternalType('string', $token, 'Expect token to be a string');

		// Sanity check
		$this->assertNotRegExp('/secret key/', $token,
			'Expect token not to contain the secret key');
	}

	/**
	 * @depends test_sign
	 */
	public function test_verify() {
		$token = stateless_auth_sign('secret key', 'login:username', 60);

		$this->assertTrue(
			stateless_auth_verify($token, 'secret key', 'login:username'),
			'Test token with correct parameters');

		$tampered_token = str_replace('login:username', 'new context', $token);

		$this->assertFalse(
			stateless_auth_verify($tampered_token, 'secret key', 'new context'),
			'Test nonsense token');

		$this->assertFalse(
			stateless_auth_verify('nonsense string', 'secret key', 'login:username'),
			'Test nonsense token');
	}

	/**
	 * @depends test_verify
	 */
	public function test_is_token_valid_server_secret() {
		$token = stateless_auth_sign('secret key', 'login:username', 60);

		$this->assertFalse(
			stateless_auth_verify($token, 'wrong secret', 'login:username'),
			'Test token with incorrect secret key');
	}

	/**
	 * @depends test_verify
	 */
	public function test_is_token_valid_context() {
		$token = stateless_auth_sign('secret key', 'login:username', 60);

		$this->assertFalse(
			stateless_auth_verify($token, 'secret key', 'wrong purpose:username'),
			'Test token with part of the context incorrect');

		$this->assertFalse(
			stateless_auth_verify($token, 'secret key', 'login:wrong username'),
			'Test token with part of the context incorrect');
	}

	/**
	 * @depends test_verify
	 */
	public function test_is_token_valid_expiry_time() {
		$token = stateless_auth_sign('secret key', 'login:username', -1);

		$this->assertFalse(
			stateless_auth_verify($token, 'secret key', 'login:username'),
			'Expect token to have expired');
	}

	/**
	 * @depends test_sign
	 */
	public function test_get_expiry() {
		$now = time();
		$token = stateless_auth_sign('secret key', 'login:username', 0);
		$expiry_time = stateless_auth_get_expiry($token);

		$this->assertGreaterThanOrEqual($now - 1, $expiry_time);
		$this->assertLessThanOrEqual($now + 1, $expiry_time);
	}

	/**
	 * @depends test_sign
	 */
	public function test_get_context() {
		$token = stateless_auth_sign('secret key', 'login:username', 60);

		$this->assertSame(stateless_auth_get_context($token), 'login:username');
	}
}


