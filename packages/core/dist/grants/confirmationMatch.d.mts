/**
 * The ONE cnf/token-binding comparison matrix (issue #324).
 *
 * Before this module the matrix lived as four sibling implementations —
 * `oauth/grants/refreshToken.mts`, `oauth-token-exchange/grant.mts`,
 * `core/middleware/protectedResourceBinding.mts`, and
 * `oauth/types/introspect.mts` — so adding a `Confirmation` variant meant
 * synchronized edits in four files. Core owns the `Confirmation` union
 * (`grants/confirmation.mts`), so the matrix lives here with it: callers
 * consume {@link matchConfirmation} and keep only their own error mapping
 * (`invalid_grant` at the token endpoint, a 401 challenge at a protected
 * resource, `active: false` at introspection).
 */
import type { Confirmation } from "./confirmation.mjs";
import type { TokenBinding } from "./tokenBinding.mjs";
/**
 * Per-`cnf`-member binding profile: the mechanism `kind` that owns the
 * member, the auth scheme a token bound by it must be presented under, and
 * the `WWW-Authenticate` challenge naming that scheme.
 *
 * All three halves are core vocabulary: core owns the `Confirmation` union
 * (`grants/confirmation.mts`), and the spec makes adding a variant a core
 * semver-minor change — so the mapping lives with the union rather than
 * being negotiated with each mechanism package. Gating on `kind` (rather
 * than on the confirmation's shape alone) is deliberate: `Confirmation` is
 * mechanism-extensible, so a third-party mechanism could emit `{ jkt }`
 * without ever validating a DPoP proof, and shape-matching alone would hand
 * it a bound token (PR #185).
 *
 * `scheme` / `challenge`: `cnf.jkt` REQUIRES the `DPoP` auth scheme
 * (RFC 9449 §7.1 — a DPoP-bound token presented as a Bearer token must be
 * refused); `cnf["x5t#S256"]` keeps `Bearer`, because RFC 8705 does not
 * redefine the wire-level token type.
 */
export declare const BINDING_PROFILES: {
    readonly jkt: {
        readonly kind: "dpop";
        readonly scheme: "dpop";
        readonly challenge: "DPoP";
    };
    readonly "x5t#S256": {
        readonly kind: "mtls";
        readonly scheme: "bearer";
        readonly challenge: "Bearer";
    };
};
/** A `cnf` member core recognizes as naming a binding. */
export type ConfirmationMember = keyof typeof BINDING_PROFILES;
export declare const CONFIRMATION_MEMBERS: readonly ConfirmationMember[];
/**
 * Outcome of comparing a token's raw `cnf` claim against the binding
 * presented on the current request.
 *
 * - `unbound` — the token names no binding (missing, non-object, or junk
 *   `cnf`). Nothing to enforce; callers that support the opt-in upgrade
 *   row ("unbound token + proof presented → issue a bound token") decide
 *   that themselves from the presented binding.
 * - `compound` — the `cnf` carries MORE than one well-formed member. This
 *   AS mints exactly one mechanism's confirmation per token, so a compound
 *   `cnf` means a forged token or an AS bug; every surface refuses rather
 *   than picking a winner.
 * - `no-proof` — the token is bound by `member` but no binding of the
 *   owning mechanism kind presented that member (stolen-token replay, or a
 *   deployment that dropped the mechanism while bound tokens are live).
 * - `mismatch` — the owning mechanism presented material for a different
 *   key or certificate (multi-key / multi-cert attack).
 * - `satisfied` — the presented material matches the token's binding.
 */
export type ConfirmationMatch = {
    readonly status: "unbound";
} | {
    readonly status: "compound";
} | {
    readonly status: "no-proof";
    readonly member: ConfirmationMember;
    readonly expected: string;
} | {
    readonly status: "mismatch";
    readonly member: ConfirmationMember;
    readonly expected: string;
} | {
    readonly status: "satisfied";
    readonly member: ConfirmationMember;
    readonly value: string;
};
/**
 * Evaluate the sender-constraint matrix for one token: does the binding
 * presented on this request satisfy the token's `cnf` claim?
 *
 * `cnf` is the RAW claim value straight off the JWT payload — validation of
 * its shape is this function's job. `binding` is the request's resolved
 * `TokenBinding` (or `null`/`undefined` when no mechanism produced one).
 *
 * Each member is compared only against a binding whose `kind` owns it (see
 * {@link BINDING_PROFILES}): the `Confirmation` union is
 * mechanism-extensible, so a non-DPoP mechanism emitting `{ jkt: "..." }`
 * (or a non-mTLS mechanism emitting `{ "x5t#S256": "..." }`) could
 * otherwise satisfy a bound token without actually presenting the right
 * proof. Restricting each member to its declared mechanism enforces the
 * kind boundary structurally, not by convention (PR #185 / Codex
 * Important #2).
 */
export declare const matchConfirmation: (cnf: unknown, binding: TokenBinding | null | undefined) => ConfirmationMatch;
/**
 * Narrow a presented binding's confirmation to the member its mechanism
 * `kind` owns, or `undefined` when the kind owns no recognized member (a
 * third-party mechanism) or the confirmation lacks that member.
 *
 * This is the value a grant may stamp onto a token it issues for the
 * request: material the owning mechanism actually validated. The kind
 * gating is the same boundary {@link matchConfirmation} enforces.
 */
export declare const ownedConfirmation: (binding: TokenBinding | null | undefined) => Confirmation | undefined;
/**
 * Validate and narrow a raw `cnf` claim value extracted from a JWT
 * payload into a `Confirmation`. Returns `undefined` when the value
 * is missing or fails any of:
 *
 * - non-object (null, array, primitive)
 * - missing both `jkt` and `x5t#S256` members
 * - member value is not a non-empty string
 *
 * Empty-string members are rejected because RFC 9449 §6 / RFC 8705 §3
 * define both `jkt` (RFC 7638 JWK Thumbprint) and `x5t#S256` (DER cert
 * SHA-256 thumbprint) as non-empty base64url strings.
 *
 * Compound binding (a cnf object carrying BOTH `jkt` and `x5t#S256`)
 * is out of scope for Stage 1 (spec §1 "out of scope"). If both are
 * present, this helper returns the `jkt` variant — matching the intent-
 * explicit dispatch policy (spec §3.5) where DPoP wins over an ambient
 * mTLS signal.
 *
 * That narrowing is a claim-shape contract, NOT an admission decision.
 * Callers that vouch for a token to a third party (the `/oauth/introspect`
 * handler) MUST screen with {@link isCompoundConfirmation} first and refuse
 * the token — narrowing alone would report a binding the AS never issued.
 * See the token-binding ADR, "compound cnf across the AS surfaces".
 */
export declare const extractConfirmation: (raw: unknown) => Confirmation | undefined;
/**
 * Whether a raw `cnf` claim value carries BOTH a well-formed `jkt` and a
 * well-formed `x5t#S256` — an ambiguous compound binding.
 *
 * This AS never mints one: a grant emits exactly one mechanism's
 * confirmation. A compound cnf therefore indicates a forged token (signing-key
 * compromise) or an AS bug, and the response is to refuse the token rather
 * than to pick a winner — the same structural stance the refresh path already
 * takes (`grants/refreshToken.mts` rejects a compound RT cnf with
 * `invalid_grant`).
 *
 * Member validation matches {@link extractConfirmation}: a cnf whose second
 * member is empty-string or non-string is a single-mechanism binding with junk
 * attached, not an ambiguous one, so it is NOT compound and `extractConfirmation`
 * narrows it to the well-formed member as usual.
 */
export declare const isCompoundConfirmation: (raw: unknown) => boolean;
//# sourceMappingURL=confirmationMatch.d.mts.map