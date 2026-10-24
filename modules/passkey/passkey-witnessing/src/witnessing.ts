import { type Audit, declaredAudit } from "@mod/audit";
import { isUnavailable, type Log, Unavailable } from "@mod/kernel";
import type { PasskeyWitness } from "@mod/passkey-witness";
import type { AfterRemoval, Asked, PasskeyWitnessing } from "@mod/passkeys";
import events from "./audit-events.ts";

export interface WitnessingParts {
	/** The one witness composed. */
	readonly witness: PasskeyWitness;
	readonly audit: Pick<Audit, "record">;
	readonly log: Pick<Log, "warn">;
	/** A new token for a mark this call sets. */
	readonly token: () => string;
}

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

/** The witness's mark kept in line with what passkeys reads, asked where passkeys settles. */
export function witnessingOver(p: WitnessingParts): PasskeyWitnessing {
	const { witness } = p;
	const audited = declaredAudit(p.audit, events);
	const inconsistent = (subject: string, at: Asked) => {
		audited.record("passkey.enrollment_inconsistent", { subject, attributes: { at } });
		p.log.warn("passkey.enrollment_inconsistent", { at });
		return new Unavailable("passkeys");
	};
	/**
	 * Marks a subject holding a passkey with no mark, under a new token. A mark beside none goes by
	 * `withdraw` where this call set it, and is otherwise read once more, then recorded and
	 * unavailable: the store may have lost the passkeys. After any write it reads both again; it marks
	 * twice at most, then is unavailable. Answers whether the subject holds a passkey, as the read the
	 * mark agreed with saw it.
	 */
	const settle = async (subject: string, at: Asked, holds: () => Promise<boolean>) => {
		let mine: string | undefined;
		for (let marks = 0; ; ) {
			const held = await holds();
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
				const again = await holds();
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
	/**
	 * After a write that emptied the list: withdraws the mark by the token read first, only where
	 * `after` answers none, and marks again where a passkey came meanwhile.
	 */
	const emptied = async (
		subject: string,
		at: Asked,
		after: () => Promise<AfterRemoval>,
		holds: () => Promise<boolean>,
	) => {
		// The mark before the holdings: a registration lists before it marks.
		const token = await witness.markedWith(subject);
		if (token === undefined) return;
		const held = await after();
		if (held === "unsure") throw inconsistent(subject, at);
		if (held !== "none") return;
		await retried(() => witness.withdraw(subject, token));
		const left = await after();
		if (left === "unsure") throw inconsistent(subject, at);
		// A pending one marks once admitted.
		if (left === "passkey") await settle(subject, at, holds);
	};
	return { settle, emptied };
}
