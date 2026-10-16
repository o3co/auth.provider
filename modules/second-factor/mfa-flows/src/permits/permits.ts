import type { Clock } from "@mod/kernel";
import type { StoredTransaction, TransactionStore } from "../store.ts";
import { hashOf } from "../transactions/records.ts";

/** What a used permit's release answered: released, or a fixed hold left standing since `fixedAt`. */
export type PermitResult =
	| { readonly lock: "released" }
	| { readonly lock: "held"; readonly fixedAt: number };

/** A session's permit to release its subject's lockout, from a proof guessing cannot beat. */
interface Permit {
	/** When the proof passed, on the kernel's clock. */
	readonly proofAt: number;
	readonly used?: PermitResult;
}

export type PermitState =
	| { readonly kind: "none" }
	| { readonly kind: "ready"; readonly id: string; readonly proofAt: number }
	| { readonly kind: "used"; readonly result: PermitResult };

export interface PermitParts {
	readonly store: TransactionStore;
	readonly clock: Clock;
	/** Whether a proof at that time is still recent (`mfa`'s window). */
	readonly recent: (at: number) => boolean;
	/** How long a session's record lives from its first permit: the longest recent window. */
	readonly keepMs: number;
}

export type Permits = ReturnType<typeof permitsOver>;

export function permitsOver(p: PermitParts) {
	const keyOf = (handle: string) => hashOf(`release-permit\n${handle}`);
	const permitOf = (record: StoredTransaction | undefined) =>
		record as unknown as Permit | undefined;
	const stored = (permit: Permit) => permit as unknown as StoredTransaction;
	return {
		/** Grants the session a permit from a proof passing now; a later proof's replaces it, used or not. */
		grant: async (handle: string) => {
			const key = keyOf(handle);
			const fresh = stored({ proofAt: p.clock.now() });
			if (await p.store.update(key, () => ({ value: fresh }))) return;
			if ((await p.store.save(key, fresh, p.keepMs)) === "created") return;
			// Another request saved one first: this later proof replaces it.
			await p.store.update(key, () => ({ value: fresh }));
		},
		/** The session's permit: none (or no longer recent), ready, or used with what it answered. */
		of: async (handle: string): Promise<PermitState> => {
			const key = keyOf(handle);
			const permit = permitOf(await p.store.read(key));
			if (!permit) return { kind: "none" };
			if (permit.used) return { kind: "used", result: permit.used };
			if (!p.recent(permit.proofAt)) return { kind: "none" };
			return { kind: "ready", id: hashOf(`${key}\n${permit.proofAt}`), proofAt: permit.proofAt };
		},
		/** Marks the permit of that proof used, keeping what it answered; a later proof's is left. */
		use: async (
			handle: string,
			ready: { readonly proofAt: number },
			result: PermitResult,
		): Promise<void> => {
			await p.store.update(keyOf(handle), (record) => {
				const permit = permitOf(record);
				const same = permit?.proofAt === ready.proofAt && !permit.used;
				return same ? { value: stored({ proofAt: ready.proofAt, used: result }) } : undefined;
			});
		},
	};
}
