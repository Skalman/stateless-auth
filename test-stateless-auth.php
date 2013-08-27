<?php
/* Copyright 2013 Dan Wolff (danwolff.se)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

require 'stateless-auth.php';

class Stateless_auth_test extends PHPUnit_Framework_TestCase {
	public function test_create() {
		$token = stateless_auth_create('secret key', 'login:username', 60);

		$this->assertInternalType('string', $token, 'Expect token to be a string');

		// Sanity check
		$this->assertNotContains('secret key', $token,
			'Expect token not to contain the secret key');
	}

	/**
	 * @depends test_create
	 */
	public function test_verify() {
		$token = stateless_auth_create('secret key', 'login:username', 60);

		$this->assertTrue(
			stateless_auth_verify('secret key', 'login:username', $token),
			'Test token with correct parameters');

		$tampered_token = str_replace('login:username', 'new context', $token);

		$this->assertFalse(
			stateless_auth_verify('secret key', 'new context', $tampered_token),
			'Test nonsense token');

		$this->assertFalse(
			stateless_auth_verify('nonsense string', 'secret key', 'login:username'),
			'Test nonsense token');
	}

	/**
	 * @depends test_verify
	 */
	public function test_is_token_valid_server_secret() {
		$token = stateless_auth_create('secret key', 'login:username', 60);

		$this->assertFalse(
			stateless_auth_verify('wrong secret', 'login:username', $token),
			'Test token with incorrect secret key');
	}

	/**
	 * @depends test_verify
	 */
	public function test_is_token_valid_context() {
		$token = stateless_auth_create('secret key', 'login:username', 60);

		$this->assertFalse(
			stateless_auth_verify('secret key', 'wrong purpose:username', $token),
			'Test token with part of the context incorrect');

		$this->assertFalse(
			stateless_auth_verify('secret key', 'login:wrong username', $token),
			'Test token with part of the context incorrect');
	}

	/**
	 * @depends test_verify
	 */
	public function test_is_token_valid_expiry_time() {
		$token = stateless_auth_create('secret key', 'login:username', -1);

		$this->assertFalse(
			stateless_auth_verify('secret key', 'login:username', $token),
			'Expect token to have expired');
	}

	/**
	 * @depends test_create
	 */
	public function test_get_expiry() {
		$now = time();
		$token = stateless_auth_create('secret key', 'login:username', 0);
		$expiry_time = stateless_auth_get_expiry($token);

		$this->assertGreaterThanOrEqual($now - 1, $expiry_time);
		$this->assertLessThanOrEqual($now + 1, $expiry_time);
	}

	/**
	 * @depends test_create
	 */
	public function test_get_context() {
		$token = stateless_auth_create('secret key', 'login:username', 60);

		$this->assertSame(stateless_auth_get_context($token), 'login:username');
	}
}
