/**
 * What a grant looks like from outside (#593, D9).
 *
 * An allowlist, written out field by field, rather than a record with a few
 * things deleted. What a grant holds includes the consent session it was made
 * in, the intent handle that made it, the fingerprints its identity is pinned
 * to, its version and the stamp of its last failed refresh — none of which is
 * a caller's business, and all of which a spread would disclose the day
 * somebody adds a field to the record.
 *
 * A field a record does not have is **omitted**, not reported empty: a pending
 * grant has no upstream account and no expiry because it has not been
 * consented to yet, and `"expires_at": null` would invite a client to compare
 * it with something.
 */
import { type EffectiveFederationGrantStatus, type FederationGrant } from "@o3co/auth-provider-core";
export declare function federationGrantStatusView(grant: FederationGrant, status: EffectiveFederationGrantStatus, maxExpiresInMs: number, 
/**
 * Whether the client may still use this grant's connection.
 *
 * A grant that has ENDED is described whether or not the client may still
 * use its connection — that answer is what lets a client stop asking. What
 * it is not is a reason to keep handing back the upstream account, the
 * consented scope set and the dates to a client an operator has just taken
 * off the allowlist. Review asked the question the design had not: removing
 * a client from the allowlist is an operator's lever, and a lever that
 * changes the status code but not the payload is half a lever.
 */
permitted: boolean): Readonly<Record<string, unknown>>;
//# sourceMappingURL=statusView.d.mts.map