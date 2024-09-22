# JWKS Server with JWT Authentication
A python-based RESTful JWKS (JSON Web Key Set) server that provides public keys with unique identifiers (kid) for verifying JSON Web Tokens (JWTs). It implements key expiry, includes an authentication endpoint, and handles the issuance of JWTs with expired keys based on a query parameter.

## Features
* **RSA Key Pair Generation:** Implements RSA key pair generation with unique *kid* and expiry timestamps.
* **JWKS Endpoint:** Serves public keys in JWKS format, excluding expired keys.
* **Authentication Endpoint:** Issues signed JWTs upon successful POST request.
  * Supports issuing JWTs signed with expired keys when the *expired* query parameter is present.
* **Key Expiry Handling:** Implements key expiry and excludes expired keys from JWKS.
* **Testing Suite:** Includes comprehensive tests with over 95% coverage.
