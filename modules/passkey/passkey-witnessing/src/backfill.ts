import { Unavailable } from "@mod/kernel";
import type { PasskeyWitness } from "@mod/passkey-witness";
import type { Backfilled } from "./contract.ts";
import { retried } from "./witnessing.ts";

/** A backfill marks anew after its own withdraw this often at most, then is unavailable. */
const backfillRemarks = 3;

type Holding = "passkey" | "pending" | "none";

/**
 * Fills a missing mark beside a passkey, and reads the passkeys again after: a mark it set beside
 * none (a reset took the passkeys meanwhile) goes by its own token, which leaves any other; one it
 * did not set is never removed, as it may be a store that lost its passkeys, and a mark still
 * standing beside none after its withdraw is reported. After its own withdraw it reads again and
 * marks anew where a passkey stands. Every mark is followed by that check, so the last one it may
 * make never stays beside none.
 */
export function backfillWith(p: {
	readonly witness: PasskeyWitness;
	/** What the subject's list names as written, read anew. */
	readonly holding: (subject: string) => Promise<Holding>;
	readonly token: () => string;
}) {
	return async (subject: string): Promise<Backfilled> => {
		let last = "none" as Holding;
		const holds = async () => {
			last = await p.holding(subject);
			return last === "passkey";
		};
		const nothing = async (): Promise<Backfilled> => {
			if (last === "pending") return "pending";
			return (await p.witness.read(subject)) ? "inconsistent" : "none";
		};
		const held = await holds();
		if (!held && last === "pending") return "pending";
		const marked = await p.witness.read(subject);
		if (held && marked) return "held";
		if (!held) return marked ? "inconsistent" : "none";
		let token = p.token();
		let ours = await retried(() => p.witness.enroll(subject, token));
		for (let remarks = 0; ; remarks++) {
			// Read again: a reset may have taken the passkeys, and another may have marked, meanwhile.
			if (await holds()) {
				if (!(await p.witness.read(subject))) throw new Unavailable("passkeys");
				return ours ? "marked" : "held";
			}
			if (!ours || last === "pending") return nothing();
			await retried(() => p.witness.withdraw(subject, token));
			// A withdraw leaves another's mark, which still stands beside none.
			if (!(await holds())) return nothing();
			// A registration may have written a passkey meanwhile: mark it anew.
			if (remarks === backfillRemarks) throw new Unavailable("passkeys");
			token = p.token();
			ours = await retried(() => p.witness.enroll(subject, token));
		}
	};
}
