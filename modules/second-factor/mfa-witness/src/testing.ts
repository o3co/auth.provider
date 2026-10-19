import { defineModule, Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { type EnrollmentWitness, enrollmentWitnesses } from "./contract.ts";

/**
 * A witness in memory, keeping its promises: each call fails as unavailable while its count of
 * failures lasts, and `lost` writes take effect with their answer lost. `beforeEnroll`,
 * `afterEnroll` and `beforeRead` run once around the next such call, as a request racing it would.
 */
export function witnessStandIn(name = "enrollment-witness") {
	const marks = new Map<string, string>();
	const failing = { read: 0, enroll: 0, clear: 0 };
	const lost = { enroll: 0, clear: 0 };
	const next: {
		beforeEnroll?: (() => void) | undefined;
		afterEnroll?: (() => void) | undefined;
		beforeRead?: (() => void) | undefined;
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
	const module = defineModule({ name }, (m) => [
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
	return problems;
}

/** What mfa needs from any witness: set-if-absent by token, clear, and reads never behind an answered write. */
export function enrollmentWitnessContract(name: string, open: () => Promise<EnrollmentWitness>) {
	describe(`enrollment witness contract: ${name}`, () => {
		it("keeps the mark by its first token, clears it, and reads every answered write", async () => {
			expect(await witnessProblems(await open())).toEqual([]);
		});
	});
}
