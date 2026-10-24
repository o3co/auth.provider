import type { AuditRecord } from "@mod/audit";
import { Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import { describe, expect, it } from "vitest";
import { resetOver } from "../src/reset.ts";

type Answer<T> = T | Error;
const answer = <T>(a: Answer<T> | undefined, fallback: T) => {
	if (a instanceof Error) throw a;
	return a ?? fallback;
};

/** A reset over scripted parts: each call takes the next scripted answer, recording what it was asked. */
const place = (
	script: {
		readonly records?: Answer<{ complete: boolean }>[];
		readonly cleared?: Answer<{ removed: number }>[];
	} = {},
) => {
	const calls: string[] = [];
	const events: AuditRecord[] = [];
	const logged = recordingLog();
	const records = [...(script.records ?? [])];
	const cleared = [...(script.cleared ?? [])];
	const { reset, part } = resetOver({
		revocations: {
			record: async (subject, options) => {
				calls.push(`record ${subject} keep=${options?.keepDelegations}`);
				return answer(records.shift(), { complete: true });
			},
		},
		holders: {
			cleared: async (subject) => {
				calls.push(`cleared ${subject}`);
				return answer(cleared.shift(), { removed: 2 });
			},
		},
		audit: { record: (event) => events.push(event) },
		log: logged.log,
	});
	const lines = () => logged.lines().filter((l) => l.event.startsWith("passkey-reset.reset"));
	const attributes = () => events.map((e) => e.attributes);
	return { reset, part, calls, events, lines, attributes };
};
const steps = ["record ann keep=true", "cleared ann", "record ann keep=true"];
const down = () => new Unavailable("passkey-witness");

describe("a passkey reset by an operator", () => {
	it("ends the subject's sessions, empties its passkey list, then ends the sessions again", async () => {
		const p = place();
		expect(await p.reset.reset("ann", { requestedBy: "ticket-7" })).toEqual({
			kind: "done",
			removed: 2,
		});
		expect(p.calls).toEqual(steps);
		expect(p.events).toEqual([
			{
				kind: "passkey.reset",
				subject: "ann",
				attributes: {
					by: "operator",
					count: "2",
					sessions: "true",
					sessionsAgain: "true",
					complete: "true",
					requestedBy: "ticket-7",
				},
			},
		]);
		expect(p.lines()).toEqual([{ level: "info", event: "passkey-reset.reset", fields: {} }]);
	});

	it("refuses a subject or a requester that is not well formed before doing anything", async () => {
		const p = place();
		for (const subject of ["", "\ud800", 7 as unknown as string]) {
			await expect(p.reset.reset(subject)).rejects.toThrow(RangeError);
		}
		for (const requestedBy of ["", "x".repeat(257), "\udc00"]) {
			await expect(p.reset.reset("ann", { requestedBy })).rejects.toThrow(RangeError);
		}
		expect(await p.reset.reset("ann", { requestedBy: "x".repeat(256) })).toMatchObject({
			kind: "done",
		});
		expect(p.calls).toEqual(steps);
		expect(p.events).toHaveLength(1);
	});

	it("stops at the first boundary where it is unavailable or leaves a session open, removing nothing", async () => {
		for (const first of [down(), { complete: false }]) {
			const p = place({ records: [first] });
			expect(await p.reset.reset("ann")).toEqual({ kind: "stopped", at: "sessions" });
			expect(p.calls).toEqual(["record ann keep=true"]);
			expect(p.attributes()).toEqual([{ by: "operator", sessions: "false", complete: "false" }]);
			expect(p.lines()).toEqual([
				{
					level: "warn",
					event: "passkey-reset.reset_incomplete",
					fields: { stoppedAt: "sessions", error: "Unavailable" },
				},
			]);
		}
	});

	it("throws a first boundary's failure that is not unavailable, recorded first", async () => {
		const p = place({ records: [new TypeError("broken")] });
		await expect(p.reset.reset("ann")).rejects.toThrow(TypeError);
		expect(p.calls).toEqual(["record ann keep=true"]);
		expect(p.attributes()).toEqual([{ by: "operator", sessions: "false", complete: "false" }]);
	});

	it("stops at the passkeys where their removal is unavailable, the second boundary moved all the same", async () => {
		const p = place({ cleared: [down()] });
		expect(await p.reset.reset("ann")).toEqual({ kind: "stopped", at: "passkeys" });
		expect(p.calls).toEqual(steps);
		expect(p.attributes()).toEqual([
			{ by: "operator", sessions: "true", sessionsAgain: "true", complete: "false" },
		]);
		expect(p.lines().map((l) => l.fields)).toEqual([
			{ stoppedAt: "passkeys", error: "Unavailable" },
		]);
	});

	it("tries the second boundary where the removal throws, then throws that failure, recorded first", async () => {
		const p = place({ cleared: [new TypeError("broken")] });
		await expect(p.reset.reset("ann")).rejects.toThrow(TypeError);
		expect(p.calls).toEqual(steps);
		expect(p.attributes()).toEqual([
			{ by: "operator", sessions: "true", sessionsAgain: "true", complete: "false" },
		]);
	});

	it("stops at the second boundary where it is unavailable or leaves a session open, with what it removed", async () => {
		for (const second of [down(), { complete: false }]) {
			const p = place({ records: [{ complete: true }, second] });
			expect(await p.reset.reset("ann")).toEqual({ kind: "stopped", at: "sessions", removed: 2 });
			expect(p.calls).toEqual(steps);
			expect(p.attributes()).toEqual([
				{ by: "operator", count: "2", sessions: "true", sessionsAgain: "false", complete: "false" },
			]);
			expect(p.lines().map((l) => l.fields)).toEqual([
				{ stoppedAt: "sessions", error: "Unavailable" },
			]);
		}
	});

	it("answers the first step that failed: the passkeys, where the second boundary is unavailable too", async () => {
		const p = place({ records: [{ complete: true }, down()], cleared: [down()] });
		expect(await p.reset.reset("ann")).toEqual({ kind: "stopped", at: "passkeys" });
		expect(p.attributes()).toEqual([
			{ by: "operator", sessions: "true", sessionsAgain: "false", complete: "false" },
		]);
		expect(p.lines().map((l) => l.fields)).toEqual([
			{ stoppedAt: "passkeys", error: "Unavailable" },
		]);
	});

	it("throws a later step's failure that is not unavailable, over an earlier one that was", async () => {
		const p = place({ records: [{ complete: true }, new TypeError("broken")], cleared: [down()] });
		await expect(p.reset.reset("ann")).rejects.toThrow(TypeError);
		expect(p.calls).toEqual(steps);
		expect(p.attributes()).toEqual([
			{ by: "operator", sessions: "true", sessionsAgain: "false", complete: "false" },
		]);
	});

	it("finishes when run again after it stopped, removing what is left", async () => {
		const p = place({ cleared: [down(), { removed: 0 }] });
		expect(await p.reset.reset("ann")).toEqual({ kind: "stopped", at: "passkeys" });
		expect(await p.reset.reset("ann")).toEqual({ kind: "done", removed: 0 });
		expect(p.calls).toEqual([...steps, ...steps]);
	});
});

describe("the passkeys' step alone, for a reset that moves the boundaries itself", () => {
	it("empties the list without moving a boundary or recording anything", async () => {
		const p = place();
		expect(await p.part.passkeys("ann")).toEqual({ kind: "done", removed: 2 });
		expect(p.calls).toEqual(["cleared ann"]);
		expect(p.events).toEqual([]);
		expect(p.lines()).toEqual([]);
	});

	it("answers stopped where the removal is unavailable, and throws any other failure", async () => {
		expect(await place({ cleared: [down()] }).part.passkeys("ann")).toEqual({ kind: "stopped" });
		await expect(
			place({ cleared: [new TypeError("broken")] }).part.passkeys("ann"),
		).rejects.toThrow(TypeError);
	});

	it("refuses a subject that is not well formed before asking anything", async () => {
		const p = place();
		await expect(p.part.passkeys("")).rejects.toThrow(RangeError);
		expect(p.calls).toEqual([]);
	});
});
