import type { AccessGrant, AudienceAddition } from "../contract.ts";

/**
 * The audiences the additions answer for a grant, each once and none of its own; a TypeError, the
 * caller's mistake, for a value that is not a non-empty string or for any at all to a grant with
 * no audience, whose token would be read back as one for none.
 */
export function addedFor(additions: readonly AudienceAddition[], grant: AccessGrant): string[] {
	const answered = additions.flatMap((a) => [...a.added(grant)]);
	for (const value of answered) {
		if (typeof value !== "string" || value === "")
			throw new TypeError("tokens: an added audience is not a non-empty string");
	}
	const added = [...new Set(answered)].filter((value) => !grant.audience.includes(value));
	if (added.length > 0 && grant.audience.length === 0)
		throw new TypeError("tokens: a grant with no audience takes no added audience");
	return added;
}

/** `aud` split into the grant's audience and what the issuer added past it; none where `aud_added` would leave the grant none. */
export const audienceOf = (claims: {
	readonly aud: string | readonly string[];
	readonly aud_added?: number | undefined;
}) => {
	const all = typeof claims.aud === "string" ? [claims.aud] : claims.aud;
	const added = claims.aud_added ?? 0;
	if (added === 0) return { grant: all, added: [] };
	if (typeof claims.aud === "string" || added >= all.length) return undefined;
	return { grant: all.slice(0, all.length - added), added: all.slice(all.length - added) };
};
