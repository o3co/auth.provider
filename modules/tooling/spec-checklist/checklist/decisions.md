# Decisions

The decisions a `deviates:` mark or an exception names, each as `- **D-<n>** <date> (<who>): <what was decided>`.

- **D-1** 2026-10-27 (owner): a client's assertion (`private_key_jwt`) names the issuer alone as its `aud` by default, since one naming the token endpoint may have been made for another authorization server; the token endpoint's URL is taken only from a client whose registration sets `client-assertion.accept-loose-audience`, and each registered client that sets it is warned of at every start.
- **D-2** 2026-10-29 (owner): the provider's own unregistered names keep no vendor prefix: authorize's resume parameters (`reauth`, `consent_denied`) and the error codes of its own steps (such as `step_up_required` and the second factor's `mfa_*`). They are read and answered at this provider's routes alone, and prefixing them would break 0.18's relying parties for no protection gained; the registered-name items are met where they bind, the token endpoint answering registered codes and token exchange's lifetime asked as `o3co_expires_in`.
