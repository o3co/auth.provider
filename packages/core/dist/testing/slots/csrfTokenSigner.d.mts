import type { CsrfTokenSigner } from "../../browser-session/types.mjs";
/**
 * A signer over a random 32-byte key drawn when it is built: HMAC-SHA256 of
 * the payload, base64url; `verify` compares fixed-length digests of the two
 * signatures with `timingSafeEqual` and answers `false` for anything that is
 * not a string. Frozen. Two doubles sign alike never.
 */
export declare function createTestCsrfTokenSigner(): CsrfTokenSigner;
//# sourceMappingURL=csrfTokenSigner.d.mts.map