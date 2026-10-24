import { defineModule, Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { type EnrollmentWitness, enrollmentWitnesses } from "./contract.ts";

/**
 * A witness in memory, keeping its promises: each call fails as unavailable while its count of
 * failures lasts, and `lost` writes take effect with their answer lost. `beforeEnroll`,
 * `afterEnroll`, `beforeRead`, `beforeWithdraw` and `beforeMarkedWith` (awaited, so a call can be
 * held there) run once around the next such call, as a request racing it would. Made `withdraw: false`, it offers no withdraw, as a ledger that has none, and
 * so no markedWith; made `markedWith: false`, no markedWith, as a ledger whose read answers no token.
 */
export function witnessStandIn(
	name = "enrollment-witness",
	options: { readonly withdraw?: boolean; readonly markedWith?: boolean } = {},
) {
	const marks = new Map<string, string>();
	const failing = { read: 0, enroll: 0, clear: 0, withdraw: 0, markedWith: 0 };
	const lost = { enroll: 0, clear: 0, withdraw: 0 };
	const next: {
		beforeEnroll?: (() => void) | undefined;
		afterEnroll?: (() => void) | undefined;
		beforeRead?: (() => void) | undefined;
		beforeWithdraw?: (() => void) | undefined;
		beforeMarkedWith?: (() => void | Promise<void>) | undefined;
	} = {};
	const fails = (call: keyof typeof failing) => {
		if (failing[call] === 0) return;
		failing[call] -= 1;
		throw new Unavailable("enrollment-witness");
	};
	const loses = (call: keyof typeof lost) => {
		if (lost[call] === 0) return;
		lost[call] -= 1;
		throw new Unavailable("enrollment-witness");
	};
	const witness: EnrollmentWitness = {
		read: async (subject) => {
			fails("read");
			const before = next.beforeRead;
			next.beforeRead = undefined;
			before?.();
			return marks.has(subject);
		},
		enroll: async (subject, token) => {
			fails("enroll");
			const before = next.beforeEnroll;
			next.beforeEnroll = undefined;
			before?.();
			if (!marks.has(subject)) marks.set(subject, token);
			const owned = marks.get(subject) === token;
			const after = next.afterEnroll;
			next.afterEnroll = undefined;
			after?.();
			loses("enroll");
			return owned;
		},
		clear: async (subject) => {
			fails("clear");
			marks.delete(subject);
			loses("clear");
		},
	};
	// Left out, not undefined, where the stand-in plays a ledger without it.
	if (options.withdraw !== false) {
		witness.withdraw = async (subject, token) => {
			fails("withdraw");
			const before = next.beforeWithdraw;
			next.beforeWithdraw = undefined;
			before?.();
			if (marks.get(subject) === token) marks.delete(subject);
			loses("withdraw");
		};
		if (options.markedWith !== false) {
			witness.markedWith = async (subject) => {
				fails("markedWith");
				const before = next.beforeMarkedWith;
				next.beforeMarkedWith = undefined;
				await before?.();
				return marks.get(subject);
			};
		}
	}
	const module = defineModule({ name, takes: [] }, (m) => [
		m.contribute(enrollmentWitnesses).by(() => witness),
	]);
	return { module, witness, marks, failing, lost, next };
}

/** Where an implementation breaks the witness's promises, by what was asked; none when it keeps them. */
export async function witnessProblems(witness: EnrollmentWitness): Promise<string[]> {
	const problems: string[] = [];
	const n = Math.random().toString(36).slice(2);
	const check = (holds: boolean, what: string) => {
		if (!holds) problems.push(what);
	};
	const one = `w-${n}-1`;
	check(!(await witness.read(one)), "a subject never marked reads as marked");
	check(await witness.enroll(one, "t1"), "the first enroll does not own the mark");
	check(await witness.read(one), "a read after an answered enroll misses it");
	check(!(await witness.enroll(one, "t2")), "a second token owns the mark");
	check(await witness.enroll(one, "t1"), "the owner's token, sent again, does not own the mark");
	await witness.clear(one);
	check(!(await witness.read(one)), "a read after an answered clear still sees the mark");
	check(await witness.enroll(one, "t3"), "a token after a clear does not own the mark");
	const two = `w-${n}-2`;
	const raced = await Promise.all([witness.enroll(two, "a"), witness.enroll(two, "b")]);
	check(raced.filter(Boolean).length === 1, "two enrolls at once do not leave exactly one owner");
	const withdraw = witness.withdraw?.bind(witness);
	if (withdraw === undefined) {
		check(witness.markedWith === undefined, "markedWith is offered without withdraw");
		return problems;
	}
	const three = `w-${n}-3`;
	await witness.enroll(three, "mine");
	await withdraw(three, "other");
	check(await witness.read(three), "a withdraw takes another token's mark");
	await withdraw(three, "mine");
	check(!(await witness.read(three)), "a withdraw by the mark's token leaves it");
	await withdraw(three, "mine");
	check(!(await witness.read(three)), "a withdraw sent again does not answer alike");
	check(await witness.enroll(three, "next"), "a token after a withdraw does not own the mark");
	const four = `w-${n}-4`;
	await witness.enroll(four, "held");
	await Promise.all([withdraw(four, "stale"), witness.enroll(four, "late")]);
	check(await witness.read(four), "a withdraw beside an enroll takes another token's mark");
	const markedWith = witness.markedWith?.bind(witness);
	if (markedWith === undefined) return problems;
	const five = `w-${n}-5`;
	check(
		(await markedWith(five)) === undefined,
		"markedWith names a token for a subject never marked",
	);
	await witness.enroll(five, "first");
	await witness.enroll(five, "second");
	check((await markedWith(five)) === "first", "markedWith misses the token an enroll owned");
	await withdraw(five, "first");
	check((await markedWith(five)) === undefined, "markedWith names a token after its withdraw");
	return problems;
}

/** What mfa needs from any witness: set-if-absent by token, clear, a withdraw of its own token's mark and the mark's token where offered, and reads never behind an answered write. */
export function enrollmentWitnessContract(name: string, open: () => Promise<EnrollmentWitness>) {
	describe(`enrollment witness contract: ${name}`, () => {
		it("keeps the mark by its first token, clears it, and reads every answered write", async () => {
			expect(await witnessProblems(await open())).toEqual([]);
		});
	});
}
