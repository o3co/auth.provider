import { type CsrfTokenSigner } from "@o3co/auth-provider-core";
/**
 * The signer of the CSRF token under `secret`, the session cookie's secret.
 * Neither the secret nor the key is reachable from what it answers: a frozen
 * plain object carrying `sign` and `verify` alone. `verify` compares in
 * constant time and answers `false` for anything that is not a string.
 *
 * The secret is held to the floor the session store's schema holds
 * `session-store.secret` to (`assertSecretEntropy`), since a composition
 * without the session store's module calls this with a secret no schema has
 * read.
 */
export declare const createSessionCsrfTokenSigner: (secret: string) => CsrfTokenSigner;
//# sourceMappingURL=csrf-token-signer.d.mts.map