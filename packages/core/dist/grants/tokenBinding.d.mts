import type { Confirmation } from "./confirmation.mjs";
/**
 * Sender-constrained binding established by a transport-layer mechanism.
 * Core owns only the cross-cutting shape (discriminator + `cnf` claim);
 * mechanism packages extend with their own evidence fields. See Wave 2
 * Token-binding Cluster spec §4.2.
 *
 * Extension boundary: downstream MAY add a new `kind` and evidence
 * fields by extending this interface; the `confirmation` claim itself
 * MUST be one of the variants in `Confirmation` (RFC 7800 / IANA
 * registry domain). Adding a new confirmation variant (e.g. RFC 9421
 * `jwk` confirmation) is a core semver-minor change, not a
 * downstream-only extension.
 */
export interface TokenBinding {
    readonly kind: string;
    readonly confirmation: Confirmation;
}
//# sourceMappingURL=tokenBinding.d.mts.map