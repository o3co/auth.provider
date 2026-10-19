import type { Linking } from "../ledger.ts";
import type { UserSource } from "../registered.ts";

/** The source's links alone, as a ledger looking users up by upstream identity holds them: none is written or removed here. */
export function ledgerLinks(source: UserSource): Linking {
	return {
		byUpstream: source.byUpstream,
		link: async (subject, upstream) => {
			const held = await source.byUpstream(upstream.idp, upstream.subject);
			return held.kind === "user" && held.user.subject === subject ? "already" : "conflict";
		},
		unlink: async (subject, upstream) => {
			const held = await source.byUpstream(upstream.idp, upstream.subject);
			return held.kind === "user" && held.user.subject === subject ? "fixed" : "none";
		},
	};
}
