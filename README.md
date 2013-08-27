Stateless auth
==============

*Stateless auth* is a small PHP library to authenticate a user in a certain context. For instance, it can be used to prevent XSRF attacks or as a login cookie.

For security, *Stateless auth* relies on SHA-256 HMAC. Without the secret key, it is impossible to create a valid token, so make sure to keep the key safe and make it have enough entropy that brute force is useless.


Concepts
--------

There are a number of concepts that are important to understand when using *Stateless auth*.

- **secret key**: A secret value that the server keeps. The security of the authentication relies on an attacker not knowing this. It should be generated to have at least 128 bits of entropy.
- **token**: The string given to the client, which it must present to authenticate in a given situation.
- **context**: The context in which the token should be valid. Should not contain secrets, as it is included in plaintext in token. You should make the context as narrow as possible in order to restrict its use:
	- if it's a logged in user, include the username/ID (e.g. `send message:John Doe` for when *John Doe* is sending a message)
	- if it's possible to restrict to a specific IP, include it (e.g. `post comment:1.2.3.4` for when an anonymous user is posting a comment)
	- if it's used in a certain form, include the name of the form (e.g. `edit profile:John Dow`)
	- if it's used for signing in, state that (e.g. `login:John Doe`)
* **expiry time**: A token should always have an expiry time, after which it will no longer be valid. Once a user gets the token, waiting for expiry is the only (good) way to invalidate it. Other ways are to change the secret key (invalidates all tokens) or to start using a different context (may be a hassle).
* **[XSRF][]** (cross-site request forgery): A type of website exploit where an attacker tricks a user to submit a form to another website. *Stateless auth* is especially designed with this in mind, and has a couple of useful functions to simplify it further: `stateless_auth_xsrf_create` and `stateless_auth_xsrf_verify`.

  [XSRF]: https://en.wikipedia.org/wiki/Cross-site_request_forgery


API
---

<code>string **stateless\_auth\_create**(string $secret_key, string $context, [int $time=60])</code>

Creates a token that the server can authenticate. The token is completely stateless, and all necessary information is stored inside the token. This means that once a token is created, it can only be invalidated by expiring.

* `$secret_key`
  The server secret.
* `$context`
  The context in which the token will be valid.
* `$time=60`
  The number of seconds for which the token will be valid.
* Returns the token as a string, containing a hash, the token's expiry time and `$context`.

<code>bool **stateless\_auth\_verify**(string $secret_key, string $context, string $token)</code>

Checks whether a token is valid. If it is misformatted, the expiry time has passed, or the token is valid only for another context, it is considered invalid.

* `$secret_key`
  The same secret as was used to create the token.
* `$context`
  The same context as was used to create the token.
* `$token`
  The token to be checked.
* Returns `true` if the token is valid for the given context, else `false`.

<code>mixed **stateless\_auth\_get\_expiry**(string $token)</code>

Gets the expiry time for a given token.

* `$token`
  The token to get the expiry time for.
* Returns the expiry time as the number of seconds since the Unix Epoch. If it cannot be extracted, `false` is returned.

<code>mixed **stateless\_auth\_get\_context**(string $token)</code>

Gets the context for a given token.

* `$token`
  The token to get the context for.
* Returns the context as the number of seconds since the Unix Epoch. If it cannot be extracted, `false` is returned.

<code>string **stateless\_auth\_xsrf\_create**(string $secret\_key, string $context, [int $time=600, string $name='xsrf\_token', bool $xhtml=true])</code>

Creates a form `<input>`, used as an XSRF guard, by default with the name 'xsrf_token'. It is a wrapper around `stateless_auth_create()`.

* `$secret_key`
  The server secret.
* `$context`
  The context in which the token will be valid.
* `$time=600`
  The number of seconds for which the token will be valid.
* `$name='xsrf_token'`
  The `<input>` name.
* `$xhtml=true`
  Whether it is a self-closing tag or not: `<input />` vs. `<input>`
* Returns the created token in an input element, e.g. `<input type="hidden" name="xsrf_token" value="..." />`.

<code>bool **stateless\_auth\_xsrf\_verify**(string $secret\_key, string $context, [string $token=$\_POST['xsrf\_token']])</code>

Checks whether a token is valid. It is a wrapper around `stateless_auth_verify()`, using `$_POST['xsrf_token']` by default.

* `$secret_key`
  The same secret as was used to create the token.
* `$context`
  The same context as was used to create the token.
* `$token=$_POST['xsrf_token']`
  The token to be checked.
* Returns `true` if the token is valid for the given context, else `false`.



Tests
-----

Tests are available in `test-stateless-auth.php`. They use [PHPUnit][], so after installing it, you can run the tests with `phpunit test-*`.

  [PHPUnit]: http://phpunit.de/


License
-------

Copyright 2013 [Dan Wolff][].

The source code of *Stateless auth* is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

  [Dan Wolff]: http://danwolff.se/
