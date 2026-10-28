import { randomBytes } from "node:crypto";
import { defineModule, Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { type PasskeyWitness, passkeyWitnesses } from "./contract.ts";

/**
 * A passkey witness in memory, keeping its promises: each call fails as unavailable while its count
 * of failures lasts, and `lost` writes take effect with their answer lost. `beforeEnroll`,
 * `afterEnroll`, `beforeRead` and `beforeWithdraw` run once around the next such call, as a request
 * racing it would.
 */
export function passkeyWitnessStandIn(name = "passkey-witness") {
	const marks = new Map<string, string>();
	const failing = { read: 0, markedWith: 0, enroll: 0, withdraw: 0 };
	const lost = { enroll: 0, withdraw: 0 };
	const next: {
		beforeEnroll?: (() => void) | undefined;
		afterEnroll?: (() => void) | undefined;
		beforeRead?: (() => void) | undefined;
		beforeWithdraw?: (() => void) | undefined;
	} = {};
	const once = (hook: keyof typeof next) => {
		const run = next[hook];
		next[hook] = undefined;
		run?.();
	};
	const fails = (call: keyof typeof failing) => {
		if (failing[call] === 0) return;
		failing[call] -= 1;
		throw new Unavailable("passkey-witness");
	};
	const loses = (call: keyof typeof lost) => {
		if (lost[call] === 0) return;
		lost[call] -= 1;
		throw new Unavailable("passkey-witness");
	};
	const witness: PasskeyWitness = {
		read: async (subject) => {
			fails("read");
			once("beforeRead");
			return marks.has(subject);
		},
		enroll: async (subject, token) => {
			fails("enroll");
			once("beforeEnroll");
			if (!marks.has(subject)) marks.set(subject, token);
			const owned = marks.get(subject) === token;
			once("afterEnroll");
			loses("enroll");
			return owned;
		},
		withdraw: async (subject, token) => {
			fails("withdraw");
			once("beforeWithdraw");
			if (marks.get(subject) === token) marks.delete(subject);
			loses("withdraw");
		},
		markedWith: async (subject) => {
			fails("markedWith");
			return marks.get(subject);
		},
	};
	const module = defineModule({ name, replicaSafe: false, takes: [] }, (m) => [
		m.contribute(passkeyWitnesses).by(() => witness),
	]);
	return { module, witness, marks, failing, lost, next };
}

/** Where an implementation breaks the passkey witness's promises, by what was asked; none when it keeps them. */
export async function passkeyWitnessProblems(witness: PasskeyWitness): Promise<string[]> {
	const problems: string[] = [];
	const n = Math.random().toString(36).slice(2);
	const check = (holds: boolean, what: string) => {
		if (!holds) problems.push(what);
	};
	// Built where no type is checked, a witness may lack it.
	if (typeof witness.markedWith !== "function")
		return ["the witness does not tell its mark's token"];
	/** Whether the witness tells `token` as its mark's. */
	const tokenIs = async (subject: string, token: string | undefined, what: string) => {
		check((await witness.markedWith(subject)) === token, what);
	};
	const one = `p-${n}-1`;
	check(!(await witness.read(one)), "a subject never marked reads as marked");
	await tokenIs(one, undefined, "markedWith answers a token for a subject never marked");
	check(await witness.enroll(one, "t1"), "the first enroll does not own the mark");
	check(await witness.read(one), "a read after an answered enroll misses it");
	await tokenIs(one, "t1", "markedWith misses the token its enroll owned");
	check(!(await witness.enroll(one, "t2")), "a second token owns the mark");
	check(await witness.enroll(one, "t1"), "the owner's token, sent again, does not own the mark");
	await witness.withdraw(one, "t2");
	check(await witness.read(one), "a withdraw by another token removed the mark");
	await tokenIs(one, "t1", "markedWith answers another token than the mark's");
	await witness.withdraw(one, "t1");
	check(!(await witness.read(one)), "a withdraw by the owner's token left the mark");
	await tokenIs(one, undefined, "markedWith answers the token of a mark withdrawn");
	await witness.withdraw(one, "t1");
	check(!(await witness.read(one)), "a withdraw where no mark is set made one");
	check(await witness.enroll(one, "t3"), "a token after a withdraw does not own the mark");
	const two = `p-${n}-2`;
	const raced = await Promise.all([witness.enroll(two, "a"), witness.enroll(two, "b")]);
	check(raced.filter(Boolean).length === 1, "two enrolls at once do not leave exactly one owner");
	// Another's mark: the token its owner set, whichever won.
	await tokenIs(two, raced[0] ? "a" : "b", "markedWith answers another token than the mark's");
	return problems;
}

/** What passkeys needs from any witness: set-if-absent by token, withdraw by token, the mark's token, clear where it offers it, and reads never behind an answered write. */
export function passkeyWitnessContract(name: string, open: () => Promise<PasskeyWitness>) {
	describe(`passkey witness contract: ${name}`, () => {
		it("keeps the mark by its first token, withdraws it only by that token, tells its token, clears it where it can, and reads every answered write", async () => {
			expect(await passkeyWitnessProblems(await open())).toEqual([]);
		});
	});
}
