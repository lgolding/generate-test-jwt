This program generates a simple JWT string for use in tests. It makes no claims,
it is not valid on any real system, and it lives for 15 years so it will be a
while before your tests start failing because the token expired.

Usage:
```
GenerateTestJwt <issuer> <key>
```

NOTE: I'd've loved to generate a token that lasts for 1000 years so your tests
never fail, but the Microsoft authentication architecture suffers from the
Year 2038 problem. See https://github.com/IdentityModel/IdentityModel/issues/137
and https://en.wikipedia.org/wiki/Year_2038_problem.
