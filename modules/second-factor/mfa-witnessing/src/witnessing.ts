import { type Audit, declaredAudit } from "@mod/audit";
import { isUnavailable, type Log, Unavailable } from "@mod/kernel";
import type { AfterReset, Asked, Witnessing } from "@mod/mfa-extensions";
import type { EnrollmentWitness } from "@mod/mfa-witness";
import events from "./audit-events.ts";

export interface StandingParts {
	/** None composed leaves the store alone to tell. */
	readonly witness: EnrollmentWitness | undefined;
	readonly audit: Pick<Audit, "record">;
	readonly log: Pick<Log, "warn">;
}

/**
 * Whether a subject's counting factors stand for its enrollment: `held`, or `none` where the witness
 * marks nothing either. Where it marks a subject holding none, the store may have lost them: that is
 * recorded and unavailable, never none. A witness that cannot be read is unavailable too.
 */
export function standingOf(p: StandingParts) {
	const inconsistent = inconsistencyOf(p);
	return async (subject: string, counts: boolean, at: Asked) => {
		if (counts) return "held" as const;
		if (p.witness === undefined || !(await p.witness.read(subject))) return "none" as const;
		throw inconsistent(subject, at);
	};
}

/** Records and logs a mark not in line with the factors, where it was asked, and gives the unavailable to throw. */
function inconsistencyOf(p: Pick<StandingParts, "audit" | "log">) {
	const audited = declaredAudit(p.audit, events);
	return (subject: string, at: Asked | "reset") => {
		audited.record("mfa.enrollment_inconsistent", { subject, attributes: { at } });
		p.log.warn("mfa.enrollment_inconsistent", { at });
		return new Unavailable("mfa");
	};
}

/** A witness unavailable is asked again this often, with the same token, which answers alike. */
const enrollRetries = 3;

/** Whether the witness's mark is `token`'s, asked again while it is unavailable. */
export async function markedBy(witness: EnrollmentWitness, subject: string, token: string) {
	for (let attempt = 0; ; attempt++) {
		try {
			return await witness.enroll(subject, token);
		} catch (error) {
			if (!isUnavailable(error) || attempt === enrollRetries) throw error;
		}
	}
}

/** A withdraw unavailable is sent again this often, with the same token, which answers alike. */
const withdrawRetries = 3;

/** Removes its own mark: by withdraw, that token's alone, where offered (sent again while unavailable); else by clear, any mark. */
async function removeOwn(witness: EnrollmentWitness, subject: string, token: string) {
	const withdraw = witness.withdraw?.bind(witness);
	if (withdraw === undefined) return witness.clear(subject);
	for (let attempt = 0; ; attempt++) {
		try {
			return await withdraw(subject, token);
		} catch (error) {
			if (!isUnavailable(error) || attempt === withdrawRetries) throw error;
		}
	}
}

export interface SettlingParts {
	/** None composed leaves nothing to settle. */
	readonly witness: EnrollmentWitness | undefined;
	/** Whether the subject holds a counting factor, as written now. */
	readonly counting: () => Promise<boolean>;
	/** A new token for a mark this call sets. */
	readonly token: () => string;
}

/** A settle marks this often at most, then is unavailable. */
const settleMarks = 2;

/**
 * Brings the witness's mark in line with the subject's counting factors after a write: a factor
 * with no mark is marked; a mark with nothing counting goes only where this call set it (a reset
 * took the factor meanwhile), as any other may be a store that lost its factors. It removes its own
 * mark by withdraw where offered, which leaves any other; then it reads the factors again and marks
 * anew where one counts, as a binding may have taken its mark for its own, or a clear may have
 * taken the binding's. It marks twice at most, then is unavailable while they still differ.
 */
export function settlingOf(p: SettlingParts) {
	return async (subject: string) => {
		const witness = p.witness;
		if (witness === undefined) return;
		// The token of its own mark, kept only while its enroll answered that the mark is that token's.
		let owned: string | undefined;
		for (let marks = 0; ; marks++) {
			const counts = await p.counting();
			const marked = await witness.read(subject);
			if (counts === marked) return;
			if (!counts) {
				if (owned === undefined) return;
				await removeOwn(witness, subject, owned);
				owned = undefined;
				if (!(await p.counting())) return;
			}
			if (marks === settleMarks) throw new Unavailable("mfa");
			const token = p.token();
			owned = (await markedBy(witness, subject, token)) ? token : undefined;
		}
	};
}

export interface WitnessingParts extends StandingParts {
	readonly witness: EnrollmentWitness;
	readonly token: () => string;
}

/** What `mfa` asks of the witness, over the one composed. */
export function witnessingWith(p: WitnessingParts): Witnessing {
	const standing = standingOf(p);
	return {
		standing: (subject, counts, at) => standing(subject, counts, at),
		settle: (subject, counting) =>
			settlingOf({ witness: p.witness, counting, token: p.token })(subject),
		cleared: clearedWith(p),
	};
}

/** After a reset: withdraws the mark's token read once, only where `none` stands after it, then fills one beside a factor standing. */
function clearedWith(p: WitnessingParts) {
	const inconsistent = inconsistencyOf(p);
	return async (subject: string, after?: () => Promise<AfterReset>) => {
		const { witness } = p;
		if (witness.withdraw === undefined || witness.markedWith === undefined) {
			return witness.clear(subject);
		}
		const token = await witness.markedWith(subject);
		if (token === undefined) return;
		if (after === undefined) return removeOwn(witness, subject, token);
		const now = await after();
		if (now === "counting") return;
		if (now === "unsure") throw inconsistent(subject, "reset");
		await removeOwn(witness, subject, token);
		const standing = async () => {
			const later = await after();
			if (later === "unsure") throw inconsistent(subject, "reset");
			return later;
		};
		if ((await standing()) === "none") return;
		await backfillWith({ witness, standing, token: p.token })(subject);
	};
}

/** A backfill marks anew after its own clear this often at most, then is unavailable. */
const backfillRemarks = 3;

/**
 * Fills a missing mark beside a counting factor, and reads the factors again after: a mark it set
 * beside nothing counting (a reset took the factors meanwhile) goes; one it did not set is never
 * cleared, as it may be a store that lost its factors. It removes its own mark by withdraw where
 * offered, which leaves any other: a mark still standing beside nothing counting after it is
 * reported. After its own removal it reads again and marks anew where a factor counts. Every mark
 * is followed by that check, so the last one it may make never stays beside nothing counting.
 */
export function backfillWith(p: {
	readonly witness: EnrollmentWitness;
	readonly standing: (subject: string) => Promise<"counting" | "unclaimed" | "none">;
	readonly token: () => string;
}) {
	return async (subject: string) => {
		const read: { last: "counting" | "unclaimed" | "none" } = { last: "none" };
		const counting = async (subject: string) => {
			read.last = await p.standing(subject);
			return read.last === "counting";
		};
		const unclaimed = () => read.last === "unclaimed";
		const nothingCounts = async (subject: string) => {
			if (unclaimed()) return "unclaimed" as const;
			return (await p.witness.read(subject)) ? ("inconsistent" as const) : ("none" as const);
		};
		const counts = await counting(subject);
		if (!counts && unclaimed()) return "unclaimed" as const;
		const marked = await p.witness.read(subject);
		if (counts && marked) return "held" as const;
		if (!counts) return marked ? ("inconsistent" as const) : ("none" as const);
		const withdraws = typeof p.witness.withdraw === "function";
		let token = p.token();
		let ours = await markedBy(p.witness, subject, token);
		for (let remarks = 0; ; remarks++) {
			// Read again: a reset may have taken the factors, and another may have marked, meanwhile.
			if (await counting(subject)) {
				if (!(await p.witness.read(subject))) throw new Unavailable("mfa");
				return ours ? ("marked" as const) : ("held" as const);
			}
			if (!ours || unclaimed()) return nothingCounts(subject);
			await removeOwn(p.witness, subject, token);
			if (!(await counting(subject))) {
				// A withdraw leaves another's mark, which still stands beside nothing counting.
				if (!withdraws && !unclaimed()) return "none" as const;
				return nothingCounts(subject);
			}
			// A binding may have written a factor and taken this mark for its own, or a clear its mark.
			if (remarks === backfillRemarks) throw new Unavailable("mfa");
			token = p.token();
			ours = await markedBy(p.witness, subject, token);
		}
	};
}
