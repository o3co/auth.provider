import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { type ClosingParticipants, closingParticipants, type Session } from "@mod/session";
import { expect, it } from "vitest";
import { closingOf } from "../src/closing.ts";
import { type Participant, participants } from "../src/contract.ts";
import participantsModule from "../src/module.ts";

const session: Session = {
	id: "h",
	context: { subject: "alice", amr: ["pwd"], authenticatedAt: 0 },
};

it("calls the participants one at a time in the order given, past a failing one, and answers each that failed by kind", async () => {
	const calls: string[] = [];
	let running = 0;
	let overlapped = false;
	const participant = (name: string, fails?: unknown): Participant => ({
		name,
		closing: async () => {
			running++;
			overlapped ||= running > 1;
			calls.push(name);
			await new Promise((resolve) => setTimeout(resolve, 5));
			running--;
			if (fails !== undefined) throw fails;
		},
	});
	const closing = closingOf([
		participant("b", new TypeError("x")),
		participant("a"),
		participant("c", "x"),
	]);
	expect(await closing.closing(session)).toEqual([
		{ participant: "b", kind: "TypeError" },
		{ participant: "c", kind: "string" },
	]);
	expect([calls, overlapped]).toEqual([["b", "a", "c"], false]);
	expect(await closingOf([participant("a")]).closing(session)).toEqual([]);
});

it("contributes the one closing participants over those the composition contributes", async () => {
	const closed: string[] = [];
	const read = contract<ClosingParticipants>("test.closing");
	const reading = defineModule(
		{ name: "reading", replicaSafe: false, takes: [closingParticipants] },
		(m) => [
			m.provide(read).by(async (c) => {
				const [closing] = await c.collect(closingParticipants);
				if (!closing) throw new Error("none");
				return closing;
			}),
			m.contribute(participants).by(() => ({
				name: "tokens",
				closing: async (s: Session) => {
					closed.push(s.id);
				},
			})),
		],
	);
	const app = await assemble({ modules: [participantsModule, reading], config: kernelConfig() });
	expect(
		(await takesUnused({ modules: [participantsModule, reading], config: kernelConfig() }))[
			"session-participants"
		],
	).toBeUndefined();
	expect(await app.get(read).closing(session)).toEqual([]);
	expect(closed).toEqual(["h"]);
});
