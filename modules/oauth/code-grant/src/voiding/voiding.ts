import { type Log, Unavailable } from "@mod/kernel";
import type { Tokens } from "@mod/tokens";
import { fromStored, toStored } from "../codes.ts";
import type { Addition } from "../contract.ts";
import type { CodeStore, VoidList } from "../store.ts";

/** A voided record that issued a token outlives the token by this much, as the grant keeps it. */
const allowanceMs = 120_000;

/** A code's voiding: listing, marking, revoking its token, and the sweep that retries it. */
export function voiding(parts: {
	readonly store: CodeStore;
	readonly voids: VoidList;
	readonly tokens: Tokens;
	readonly log: Log;
	readonly now: () => number;
	readonly additions: readonly Addition[];
}) {
	const { store, voids, tokens, log, now, additions } = parts;
	/** Marks a known record void, even if it is already; one that issued a token lives as long. */
	const mark = async (name: string) => {
		const at = now();
		const marked = await store.update(name, (kept) => {
			const r = fromStored(kept);
			if (!r) return undefined;
			const value = toStored({ ...r, void: true });
			if (!r.token) return { value };
			return { value, lifetimeMs: Math.max(1, r.token.expiresAt - at + allowanceMs) };
		});
		return marked && fromStored(marked.after);
	};
	/** Ends what the additions gave for a code, then takes it off the void list. */
	const finish = async (name: string) => {
		for (const addition of additions) await addition.revoke?.(name);
		await voids.done(name);
	};
	/** Voids a code: listed first, it stays listed until its token is revoked or its record is gone. */
	const settle = async (name: string) => {
		await voids.add(name);
		const record = await mark(name);
		if (!record) {
			log.info("code-grant.void_without_record", {});
			await finish(name);
			return;
		}
		// Not issued yet: the request issuing it sees the mark and voids again.
		if (!record.token) return;
		const revoked = await tokens.revokeReferenced(record.token.reference);
		if (revoked.kind === "unsupported") throw new Unavailable("code-grant");
		await finish(name);
	};
	const sweep = async () => {
		const { failed } = await voids.each(settle);
		if (failed > 0) log.warn("code-grant.void_retry_failed", { count: failed });
	};
	return { settle, sweep };
}
