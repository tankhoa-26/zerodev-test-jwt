deploy this in prod server....

- where "ec and rsa" are algorithms `https://your-domain/rotate/rsa` is for making keys by rotating everytime
- https://your-domain/jwks/rsa or https://your-domain/jwks/ec this endpoint returns JWKS endpoint
- https://your-domain/token/rsa or https://your-domain/token/ec this endpoint returns JWT token which is integrated with JWKS endpoint
- https://your-domain/verify/rsa https://your-domain/verify/ec use to verify token in a post request

Note: for JWT token, when creating a sign (createSign) should pass user's auth
