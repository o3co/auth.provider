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
 */
export const extractConfirmation = (raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
        return undefined;
    const obj = raw;
    const jkt = obj.jkt;
    if (typeof jkt === "string" && jkt.length > 0) {
        return { jkt };
    }
    const x5t = obj["x5t#S256"];
    if (typeof x5t === "string" && x5t.length > 0) {
        return { "x5t#S256": x5t };
    }
    return undefined;
};
