# Decisions

The decisions a `deviates:` mark or an exception names, each as `- **D-<n>** <date> (<who>): <what was decided>`.

- **D-1** 2026-10-27 (owner): a client's assertion (`private_key_jwt`) names the issuer alone as its `aud` by default, since one naming the token endpoint may have been made for another authorization server; the token endpoint's URL is taken only from a client whose registration sets `client-assertion.accept-loose-audience`, and each registered client that sets it is warned of at every start.
- **D-2** 2026-10-27 (owner): until the `claims` parameter's support for standard claims lands (#2356), the provider does not return claims a client asks for through the `claims` parameter; the change that adds it removes this decision, its mark and the expected entry.
