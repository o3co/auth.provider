import { type Log, Unavailable } from "@mod/kernel";
import type { Tokens } from "@mod/tokens";
import { fromStored, toStored } from "../codes.ts";
import type { Addition } from "../contract.ts";
import { markVoid } from "../redemption-record/redemption-record.ts";
import type { CodeStore, RedemptionRecords, VoidList } from "../store.ts";

/** A code's voiding: listing, marking, revoking its token, and the sweep that retries it. */
export function voiding(parts: {
	readonly store: CodeStore;
	readonly redemptionRecords: RedemptionRecords;
	readonly voids: VoidList;
	readonly tokens: Tokens;
	readonly log: Log;
	readonly additions: readonly Addition[];
}) {
	const { store, redemptionRecords, voids, tokens, log, additions } = parts;
	/**
	 * Marks a redemption void wherever it is kept, even if it is already: its record, and its code's,
	 * which a 0.19 instance reads and kept its token on. Answers the token found, from either, and
	 * whether any record was there.
	 */
	const mark = async (name: string) => {
		const fromRecord = await markVoid(redemptionRecords, name);
		const coded = await store.update(name, (stored) => {
			const r = fromStored(stored);
			return r && { value: toStored({ ...r, void: true }) };
		});
		// TODO(0.22): stop reading a token here; until then, one a 0.19 instance kept on its code, or
		// noted there too, is read and revoked too.
		const fromCode = coded && fromStored(coded.after);
		const token = fromRecord?.token ?? fromCode?.token;
		return { found: fromRecord !== undefined || Boolean(fromCode), token };
	};
	/** Ends what the additions gave for a code, then takes it off the void list. */
	const finish = async (name: string) => {
		for (const addition of additions) await addition.revoke?.(name);
		await voids.done(name);
	};
	/** Voids a code: listed first, it stays listed until its token is revoked or its record is gone. */
	const settle = async (name: string) => {
		await voids.add(name);
		const { found, token } = await mark(name);
		if (!found) {
			log.info("code-grant.void_without_record", {});
			await finish(name);
			return;
		}
		// Not issued yet: the request issuing it sees the mark and voids again.
		if (!token) return;
		const revoked = await tokens.revokeReferenced(token.reference);
		if (revoked.kind === "unsupported") throw new Unavailable("code-grant");
		await finish(name);
	};
	const sweep = async () => {
		const { failed } = await voids.each(settle);
		if (failed > 0) log.warn("code-grant.void_retry_failed", { count: failed });
	};
	return { settle, sweep };
}
