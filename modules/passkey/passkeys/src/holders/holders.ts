import { type Audit, declaredAudit } from "@mod/audit";
import { isUnavailable, type Log, Unavailable } from "@mod/kernel";
import type { PasskeyWitness } from "@mod/passkey-witness";
import events from "../audit-events.ts";
import type { PasskeyHolders } from "../contract.ts";
import type { Emptied, KeptPasskeys } from "../records.ts";

export interface HolderParts {
	readonly records: KeptPasskeys;
	/** None composed leaves the store alone to tell. */
	readonly witness: PasskeyWitness | undefined;
	readonly audit: Pick<Audit, "record">;
	readonly log: Pick<Log, "warn">;
	/** A new token for a mark this call sets. */
	readonly token: () => string;
	/** A new holder's handle, for a reset of a subject that has none. */
	readonly handle: () => string;
}

/** Where a settle was asked, as an inconsistency found there is recorded. */
export type Asked = "held" | "registration" | "removal" | "reset" | "settle";

/** A witness unavailable is asked again this often, with the same token, which answers alike. */
const enrollRetries = 3;
/** A settle marks this often at most, then is unavailable. */
const settleMarks = 2;

/** `ask`'s answer, asked again while it is unavailable. */
async function retried<T>(ask: () => Promise<T>) {
	for (let attempt = 0; ; attempt++) {
		try {
			return await ask();
		} catch (error) {
			if (!isUnavailable(error) || attempt === enrollRetries) throw error;
		}
	}
}

/** The subjects' holdings, and the settle that keeps the witness's mark in line with them. */
export function holdersOver(p: HolderParts) {
	const audited = declaredAudit(p.audit, events);
	const holds = async (subject: string) => (await p.records.listed(subject)).length > 0;
	const inconsistent = (subject: string, at: Asked) => {
		audited.record("passkey.enrollment_inconsistent", { subject, attributes: { at } });
		p.log.warn("passkey.enrollment_inconsistent", { at });
		return new Unavailable("passkeys");
	};
	/**
	 * After a write that emptied the list left `emptied`: withdraws the mark by the token read first,
	 * only where the holder then holds none for sure, and marks again where a passkey came meanwhile.
	 */
	const withdrawn = async (
		witness: PasskeyWitness,
		subject: string,
		at: Asked,
		emptied: Emptied,
	) => {
		// The mark before the holdings: a registration lists before it marks.
		const token = await witness.markedWith(subject);
		if (token === undefined) return false;
		const held = await p.records.afterRemoval(subject, emptied);
		if (held === "unsure") throw inconsistent(subject, at);
		if (held !== "none") return held === "passkey";
		await retried(() => witness.withdraw(subject, token));
		const after = await p.records.afterRemoval(subject, emptied);
		if (after === "unsure") throw inconsistent(subject, at);
		// A pending one marks once admitted.
		return after === "passkey" ? settle(subject, at) : false;
	};
	/**
	 * Marks a subject holding a passkey with no mark, under a new token. A mark beside none goes by
	 * `withdraw` where this call set it, as `withdrawn` says where this call emptied the list
	 * (`emptied`), and is otherwise read once more, then recorded and unavailable: the store may have
	 * lost the passkeys. After any write it reads both again; it marks twice at most, then is
	 * unavailable. Answers whether the subject holds a passkey, as the read the mark agreed with saw it.
	 */
	const settle = async (subject: string, at: Asked, emptied?: Emptied): Promise<boolean> => {
		const witness = p.witness;
		if (witness === undefined) return holds(subject);
		if (emptied !== undefined) return withdrawn(witness, subject, at, emptied);
		let mine: string | undefined;
		for (let marks = 0; ; ) {
			const held = await holds(subject);
			const marked = await witness.read(subject);
			if (held === marked) return held;
			if (!held) {
				// After its own withdraw, both are read again: another may have marked meanwhile.
				if (mine !== undefined) {
					await witness.withdraw(subject, mine);
					mine = undefined;
					continue;
				}
				// Read once more: a last removal may lie between emptying the list and its withdraw.
				const again = await holds(subject);
				const still = await witness.read(subject);
				if (again === still) return again;
				if (!again) throw inconsistent(subject, at);
			}
			if (marks === settleMarks) throw new Unavailable("passkeys");
			marks += 1;
			const token = p.token();
			mine = (await retried(() => witness.enroll(subject, token))) ? token : undefined;
		}
	};
	const holders: PasskeyHolders = {
		// What the settle saw, the mark agreeing: never a read of the passkeys alone after it.
		held: (subject) => settle(subject, "held"),
		cleared: async (subject) => {
			const { removed, emptied } = await p.records.cleared(subject, p.handle());
			// A reset ends the mark whatever the list held: a mark beside none is what it mends.
			await settle(subject, "reset", emptied);
			return { removed };
		},
		settle: async (subject) => {
			await settle(subject, "settle");
		},
		witnessed: p.witness !== undefined,
	};
	return { holders, settle };
}
