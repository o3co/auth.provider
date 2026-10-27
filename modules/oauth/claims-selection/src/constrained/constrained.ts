import type { Log } from "@mod/kernel";
import type { ClaimsSelections } from "../contract.ts";
import type { ConstrainedFamilyList, StoredSelection } from "../store.ts";

const succeeded = (done: Promise<void>) =>
	done.then(
		() => true,
		() => false,
	);

/** The run over the constrained families' list, and its sweep, over the list and the families' records. */
export function constrainedOver(parts: {
	readonly list: ConstrainedFamilyList;
	readonly log: Pick<Log, "warn">;
	/** Off, no store is touched. */
	readonly off: boolean;
	readonly readFamily: (familyId: string) => Promise<StoredSelection | undefined>;
}) {
	const { list, log, off, readFamily } = parts;
	const constrainedFamilies: ClaimsSelections["constrainedFamilies"] = async (handle) => {
		const failed = { shards: 0, reads: 0, handles: 0, removals: 0 };
		const run = { handled: 0, expired: 0, failed };
		if (off) return run;
		const each = await list.each(async (familyId) => {
			const kept = await readFamily(familyId).catch(() => {
				failed.reads++;
				return null;
			});
			if (kept === null) return;
			if (kept !== undefined && !(await succeeded(handle(familyId)))) {
				failed.handles++;
				return;
			}
			if (!(await succeeded(list.done(familyId)))) failed.removals++;
			else if (kept === undefined) run.expired++;
			else run.handled++;
		});
		failed.shards = each.failed;
		return run;
	};
	const sweep = async () => {
		if (off) return;
		const { failed } = await list.each(async (familyId) => {
			if ((await readFamily(familyId)) === undefined) await list.done(familyId);
		});
		if (failed > 0) log.warn("claims-selection.sweep_failed", { count: failed });
	};
	return { constrainedFamilies, sweep };
}
