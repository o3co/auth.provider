import type { GrantInput, Refused, SessionIssuance } from "@mod/grants";
import type { Binding } from "@mod/sender-binding";
import { type AccessGrant, type IssuanceRequest, referenceOf, type Tokens } from "@mod/tokens";

/** What a request's grant issued through `issue`: the subjects it issued under, and the names of the claims it added. */
export interface IssuedBundle {
	readonly subjects: Set<string>;
	readonly added: Set<string>;
}

export const bundleOf = (): IssuedBundle => ({ subjects: new Set(), added: new Set() });

/**
 * A grant's `admits` and `issue`, with the binding; `issue` tells `told` of a token from a session,
 * and notes in `bundle` each token's subject and the names of the claims the grant added to it.
 */
export function issuanceFor(
	tokens: Tokens,
	grantType: string,
	binding: Binding | undefined,
	told: readonly SessionIssuance[] = [],
	bundle: IssuedBundle = bundleOf(),
) {
	const bound = binding ? { binding } : {};
	const requestOf = (
		grant: AccessGrant,
		{ session, continuing }: Pick<IssuanceRequest, "session" | "continuing">,
	) => ({
		grant,
		grantType,
		...(session === undefined ? {} : { session }),
		...(continuing === undefined ? {} : { continuing }),
	});
	const admits: GrantInput["admits"] = async (grant, from = {}) => {
		const judged = await tokens.admits(requestOf(grant, from));
		return judged.kind === "allowed" ? judged : { kind: "refused", refusal: judged };
	};
	const issue: GrantInput["issue"] = async (grant, from = {}) => {
		const { session, continuing: _, ...limits } = from;
		// The subject as handed to tokens, never the grant read again once it is signed.
		const { subject } = grant;
		const issued = await tokens.issue(requestOf(grant, from), { ...limits, ...bound });
		if (issued.kind !== "issued") return { kind: "refused", refusal: issued };
		bundle.subjects.add(subject);
		// Named from what tokens judged and signed, never the grant read again.
		for (const name of issued.access.addedClaims ?? []) bundle.added.add(name);
		if (session === undefined) return issued;
		const { id, expiresAt } = issued.access;
		try {
			for (const one of told) await one.issued(session, { id, expiresAt });
		} catch (error) {
			// The failure told is the one thrown on: a token whose revocation fails too is handed to no one.
			await tokens.revokeReferenced(referenceOf(issued.access)).catch(() => undefined);
			throw error;
		}
		return issued;
	};
	return { admits, issue };
}

/** The one answer to a refused issuance, whatever the grant. */
export const refusedAnswer = ({ refusal }: Refused) =>
	({ kind: "error", error: "invalid_grant", description: refusal.description }) as const;
