Stateless auth
==============

*Stateless auth* is a small PHP library to authenticate a user in a certain context. For instance, it can be used to prevent XSRF attacks or as a login cookie.

For security, *Stateless auth* relies on SHA-256 HMAC. Without the secret key, it is impossible to create a valid token, so make sure to keep the key safe and make it have enough entropy that brute force is useless.


Tests
-----

Tests are available in `test-stateless-auth.php`. They use [PHPUnit][], so after installing it, you can run the tests with `phpunit test-*`.


License
-------

Copyright 2013 [Dan Wolff][].

The source code of *Stateless auth* is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.



  [PHPUnit] http://phpunit.de/
  [Dan Wolff] http://danwolff.se/
