import type { AuditRecord } from "@mod/audit";
import { Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import type { LockoutPolicy } from "@mod/rate-limit";
import { describe, expect, it } from "vitest";
import { resetOver } from "../src/reset.ts";

const policy = { budget: 10 } as unknown as LockoutPolicy;
type Answer<T> = T | Error;
const answer = <T>(a: Answer<T> | undefined, fallback: T) => {
	if (a instanceof Error) throw a;
	return a ?? fallback;
};

/** A reset over scripted parts: each call takes the next scripted answer, recording what it was asked. */
const place = (
	script: {
		readonly records?: Answer<{ complete: boolean }>[];
		readonly clear?: Answer<{ count: number; kinds: string[] }>;
		readonly release?: Answer<object>;
		/** Parts by name, each call taking the next scripted answer (a done count, stopped, or a failure). */
		readonly parts?: Readonly<Record<string, Answer<number | "stopped">[]>>;
	} = {},
) => {
	const calls: string[] = [];
	const events: AuditRecord[] = [];
	const logged = recordingLog();
	const records = [...(script.records ?? [])];
	const parts = Object.entries(script.parts ?? {}).map(([name, answers]) => {
		const left = [...answers];
		return {
			name,
			remove: async (subject: string) => {
				calls.push(`part ${name} ${subject}`);
				const given = answer(left.shift(), 0);
				return given === "stopped"
					? ({ kind: "stopped" } as const)
					: ({ kind: "done", removed: given } as const);
			},
		};
	});
	const reset = resetOver({
		parts,
		revocations: {
			record: async (subject, options) => {
				calls.push(`record ${subject} keep=${options?.keepDelegations}`);
				return answer(records.shift(), { complete: true });
			},
		},
		factors: {
			clear: async (subject) => {
				calls.push(`clear ${subject}`);
				return answer(script.clear, { count: 2, kinds: ["backup", "code"] });
			},
		},
		lockouts: {
			releaseUnder: async (name, key, given, terms) => {
				calls.push(`release ${name} ${key} ${given === policy} ${terms.kind}`);
				return answer(script.release, {}) as never;
			},
		},
		lockout: { name: "mfa", policy },
		audit: { record: (event) => events.push(event) },
		log: logged.log,
	});
	const lines = () => logged.lines().filter((l) => l.event.startsWith("mfa-flows.reset"));
	const attributes = () => events.map((e) => e.attributes);
	return { reset, calls, events, lines, attributes };
};
const cleared = { by: "operator", kinds: "backup code", count: "2" };

describe("a reset by an operator", () => {
	const removed = { count: 2, kinds: ["backup", "code"] };

	it("ends the subject's sessions, removes every factor, releases the lockout, then ends the sessions again", async () => {
		const p = place();
		expect(await p.reset.run("ann", { requestedBy: "ticket-7" })).toEqual({
			kind: "done",
			removed: 2,
			kinds: ["backup", "code"],
			parts: {},
		});
		expect(p.calls).toEqual([
			"record ann keep=true",
			"clear ann",
			"release mfa ann true whole",
			"record ann keep=true",
		]);
		expect(p.events).toEqual([
			{
				kind: "mfa.reset",
				subject: "ann",
				attributes: {
					...cleared,
					sessions: "true",
					sessionsAgain: "true",
					complete: "true",
					requestedBy: "ticket-7",
				},
			},
		]);
		expect(p.lines()).toEqual([{ level: "info", event: "mfa-flows.reset", fields: {} }]);
	});

	it("stops before the factors when the first revocation could not close every session", async () => {
		const p = place({ records: [{ complete: false }] });
		expect(await p.reset.run("joy")).toEqual({ kind: "stopped", at: "sessions" });
		expect(p.calls).toEqual(["record joy keep=true"]);
		expect(p.attributes()).toEqual([{ by: "operator", sessions: "false", complete: "false" }]);
	});

	it("stops at a second revocation that could not close every session, after the factors went", async () => {
		const p = place({ records: [{ complete: true }, { complete: false }] });
		expect(await p.reset.run("kit")).toEqual({ kind: "stopped", at: "sessions", removed });
		expect(p.attributes()).toEqual([
			{ ...cleared, sessions: "true", sessionsAgain: "false", complete: "false" },
		]);
	});

	it("moves the second boundary when releasing the lockout fails, and answers the first failure", async () => {
		const p = place({ release: new Unavailable("rate-limit") });
		expect(await p.reset.run("fay")).toEqual({ kind: "stopped", at: "lock", removed });
		expect(p.calls.at(-1)).toBe("record fay keep=true");
		expect(p.attributes()).toEqual([
			{ ...cleared, sessions: "true", sessionsAgain: "true", complete: "false" },
		]);
		expect(p.lines().map((l) => l.fields)).toEqual([{ stoppedAt: "lock", error: "Unavailable" }]);
	});

	it("stops at a failed second boundary after the factors went, and records the count", async () => {
		const p = place({ records: [{ complete: true }, new Unavailable("subject-revocation")] });
		expect(await p.reset.run("gus")).toEqual({ kind: "stopped", at: "sessions", removed });
		expect(p.attributes()).toEqual([
			{ ...cleared, sessions: "true", sessionsAgain: "false", complete: "false" },
		]);
		expect(p.lines().map((l) => l.fields)).toEqual([
			{ stoppedAt: "sessions", error: "Unavailable" },
		]);
	});

	it("answers and logs the first failure when the second boundary fails too", async () => {
		const p = place({
			records: [{ complete: true }, new Unavailable("subject-revocation")],
			release: new Unavailable("rate-limit"),
		});
		expect(await p.reset.run("ivy")).toEqual({ kind: "stopped", at: "lock", removed });
		expect(p.lines().map((l) => l.fields)).toEqual([{ stoppedAt: "lock", error: "Unavailable" }]);
		expect(p.attributes().at(-1)).toMatchObject({ sessionsAgain: "false" });
	});

	it("keeps the factors it could not remove and their lockout, ending the sessions twice all the same", async () => {
		const p = place({ clear: new Unavailable("mfa") });
		expect(await p.reset.run("hal")).toEqual({ kind: "stopped", at: "factors" });
		expect(p.calls).toEqual(["record hal keep=true", "clear hal", "record hal keep=true"]);
		expect(p.attributes()).toEqual([
			{ by: "operator", sessions: "true", sessionsAgain: "true", complete: "false" },
		]);
		expect(p.lines().map((l) => l.fields)).toEqual([
			{ stoppedAt: "factors", error: "Unavailable" },
		]);
	});

	it("refuses a malformed subject or requester before anything is done", async () => {
		const p = place();
		for (const [subject, requestedBy, what] of [
			["", undefined, "subject"],
			["eli", "", "requestedBy"],
			["eli", "r".repeat(257), "requestedBy"],
			["eli", "\ud800", "requestedBy"],
		] as const) {
			const options = requestedBy === undefined ? {} : { requestedBy };
			await expect(p.reset.run(subject, options)).rejects.toThrow(new RangeError(what));
		}
		const odd = ["eli"] as unknown as string;
		await expect(p.reset.run(odd)).rejects.toThrow(new RangeError("subject"));
		expect([p.calls, p.events]).toEqual([[], []]);
	});
});

describe("a reset run, answering how it ended", () => {
	const removed = { count: 2, kinds: ["backup", "code"] };

	it("answers done with how many factors went and their kinds", async () => {
		const p = place();
		expect(await p.reset.run("ann", { requestedBy: "ticket-7" })).toEqual({
			kind: "done",
			removed: 2,
			kinds: ["backup", "code"],
			parts: {},
		});
		expect(p.attributes().at(-1)).toMatchObject({ complete: "true", requestedBy: "ticket-7" });
	});

	it("answers where an unavailable step stopped it, with what went once the factors went", async () => {
		const at = async (script: Parameters<typeof place>[0]) => place(script).reset.run("dee");
		expect(await at({ records: [new Unavailable("subject-revocation")] })).toEqual({
			kind: "stopped",
			at: "sessions",
		});
		expect(await at({ records: [{ complete: false }] })).toEqual({
			kind: "stopped",
			at: "sessions",
		});
		expect(await at({ clear: new Unavailable("mfa") })).toEqual({ kind: "stopped", at: "factors" });
		expect(await at({ release: new Unavailable("rate-limit") })).toEqual({
			kind: "stopped",
			at: "lock",
			removed,
		});
		expect(await at({ records: [{ complete: true }, { complete: false }] })).toEqual({
			kind: "stopped",
			at: "sessions",
			removed,
		});
	});

	it("records and logs a stopped run as before, and a second run finishes it", async () => {
		const p = place({ records: [new Unavailable("subject-revocation")] });
		expect(await p.reset.run("dee")).toEqual({ kind: "stopped", at: "sessions" });
		expect(p.attributes()).toEqual([{ by: "operator", sessions: "false", complete: "false" }]);
		expect(p.lines().map((l) => l.fields)).toEqual([
			{ stoppedAt: "sessions", error: "Unavailable" },
		]);
		expect(await p.reset.run("dee")).toEqual({
			kind: "done",
			removed: 2,
			kinds: ["backup", "code"],
			parts: {},
		});
	});

	it("throws a later step's failure that is not unavailable, keeping the first failure's record and log", async () => {
		const p = place({
			clear: new Unavailable("mfa"),
			records: [{ complete: true }, new TypeError("broken")],
		});
		await expect(p.reset.run("hal")).rejects.toThrow(new TypeError("broken"));
		expect(p.attributes().at(-1)).toMatchObject({ complete: "false", sessionsAgain: "false" });
		expect(p.lines().map((l) => l.fields)).toEqual([
			{ stoppedAt: "factors", error: "Unavailable" },
		]);
	});

	it("throws a step's failure that is not unavailable, once recorded and logged", async () => {
		const p = place({ clear: new TypeError("broken") });
		await expect(p.reset.run("hal")).rejects.toThrow(new TypeError("broken"));
		expect(p.attributes().at(-1)).toMatchObject({ complete: "false" });
		expect(p.lines().map((l) => l.fields)).toEqual([{ stoppedAt: "factors", error: "TypeError" }]);
	});
});

describe("a reset's parts", () => {
	const removed = { count: 2, kinds: ["backup", "code"] };
	const sessionsTwice = ["record ann keep=true", "record ann keep=true"];
	const records = (calls: readonly string[]) => calls.filter((c) => c.startsWith("record"));

	it("removes each part by its name's order, after the factors and before the lockout's release, answering their counts", async () => {
		const p = place({ parts: { zeta: [3], alpha: [1] } });
		expect(await p.reset.run("ann")).toEqual({
			kind: "done",
			removed: 2,
			kinds: ["backup", "code"],
			parts: { alpha: 1, zeta: 3 },
		});
		expect(p.calls).toEqual([
			"record ann keep=true",
			"clear ann",
			"part alpha ann",
			"part zeta ann",
			"release mfa ann true whole",
			"record ann keep=true",
		]);
		expect(p.attributes().at(-1)).toMatchObject({ parts: "alpha=1 zeta=3", complete: "true" });
		expect(p.attributes().at(-1)).not.toHaveProperty("partsStopped");
	});

	it("answers and records a part by any name, one an object's prototype goes by too", async () => {
		// A computed key: an own entry, as a part's name is, never the prototype.
		const p = place({ parts: { ["__proto__"]: [2], constructor: [1] } });
		const done = await p.reset.run("ann");
		expect(done.kind === "done" && Object.entries(done.parts)).toEqual([
			["__proto__", 2],
			["constructor", 1],
		]);
		expect(p.attributes().at(-1)).toMatchObject({
			parts: "__proto__=2 constructor=1",
			complete: "true",
		});
	});

	it("keeps calling the rest past a part that stopped, keeps the lockout, and answers stopped at parts", async () => {
		const p = place({ parts: { alpha: ["stopped"], zeta: [3] } });
		expect(await p.reset.run("ann")).toEqual({ kind: "stopped", at: "parts", removed });
		expect(p.calls).toEqual([
			"record ann keep=true",
			"clear ann",
			"part alpha ann",
			"part zeta ann",
			"record ann keep=true",
		]);
		expect(p.attributes().at(-1)).toMatchObject({
			parts: "zeta=3",
			partsStopped: "alpha",
			sessionsAgain: "true",
			complete: "false",
		});
		expect(p.lines().map((l) => l.fields)).toEqual([{ stoppedAt: "parts", error: "Unavailable" }]);
	});

	it("keeps calling the rest past a part that throws, and throws it once recorded", async () => {
		const p = place({ parts: { alpha: [new TypeError("broken")], zeta: [3] } });
		await expect(p.reset.run("ann")).rejects.toThrow(new TypeError("broken"));
		expect(p.calls).toContain("part zeta ann");
		expect(p.calls).not.toContain("release mfa ann true whole");
		expect(records(p.calls)).toEqual(sessionsTwice);
		expect(p.attributes().at(-1)).toMatchObject({
			partsStopped: "alpha",
			sessionsAgain: "true",
			complete: "false",
		});
	});

	it("calls the parts though the factors' removal stopped, and answers that first failure", async () => {
		const p = place({ clear: new Unavailable("mfa"), parts: { alpha: [1] } });
		expect(await p.reset.run("ann")).toEqual({ kind: "stopped", at: "factors" });
		expect(p.calls).toEqual([
			"record ann keep=true",
			"clear ann",
			"part alpha ann",
			"record ann keep=true",
		]);
		expect(p.attributes().at(-1)).toMatchObject({ parts: "alpha=1", complete: "false" });
	});

	it("calls no part where the first boundary does not hold", async () => {
		const p = place({ records: [{ complete: false }], parts: { alpha: [1] } });
		expect(await p.reset.run("ann")).toEqual({ kind: "stopped", at: "sessions" });
		expect(p.calls).toEqual(["record ann keep=true"]);
	});

	it("never moves a boundary for a part: the reset moves its two alone", async () => {
		const p = place({ parts: { alpha: [1], beta: ["stopped"], gamma: [new TypeError("x")] } });
		await expect(p.reset.run("ann")).rejects.toThrow(TypeError);
		expect(records(p.calls)).toEqual(sessionsTwice);
	});

	it("throws a part's failure that is not unavailable over an earlier unavailable step", async () => {
		const p = place({ clear: new Unavailable("mfa"), parts: { alpha: [new TypeError("broken")] } });
		await expect(p.reset.run("ann")).rejects.toThrow(new TypeError("broken"));
		expect(p.attributes().at(-1)).toMatchObject({
			partsStopped: "alpha",
			sessionsAgain: "true",
			complete: "false",
		});
		expect(p.lines().map((l) => l.fields)).toEqual([
			{ stoppedAt: "factors", error: "Unavailable" },
		]);
	});

	it("throws the first of two parts' failures, and names both as stopped", async () => {
		const p = place({
			parts: { alpha: [new TypeError("first")], beta: [new RangeError("second")] },
		});
		await expect(p.reset.run("ann")).rejects.toThrow(new TypeError("first"));
		expect(p.attributes().at(-1)).toMatchObject({ partsStopped: "alpha beta", complete: "false" });
		expect(records(p.calls)).toEqual(sessionsTwice);
	});

	it("calls every part after the factors' removal throws, and throws that failure", async () => {
		const p = place({ clear: new TypeError("broken"), parts: { alpha: [1], beta: [2] } });
		await expect(p.reset.run("ann")).rejects.toThrow(new TypeError("broken"));
		expect(p.calls).toEqual([
			"record ann keep=true",
			"clear ann",
			"part alpha ann",
			"part beta ann",
			"record ann keep=true",
		]);
		expect(p.attributes().at(-1)).toMatchObject({ parts: "alpha=1 beta=2", complete: "false" });
	});

	it("finishes on a second run: a part already emptied answers none, and the lockout is released once all are done", async () => {
		const p = place({ parts: { alpha: [2, 0], beta: ["stopped", 1] } });
		expect(await p.reset.run("ann")).toEqual({ kind: "stopped", at: "parts", removed });
		expect(p.calls).not.toContain("release mfa ann true whole");
		expect(await p.reset.run("ann")).toEqual({
			kind: "done",
			removed: 2,
			kinds: ["backup", "code"],
			parts: { alpha: 0, beta: 1 },
		});
		expect(p.calls.filter((c) => c.startsWith("release"))).toEqual(["release mfa ann true whole"]);
		expect(p.attributes().at(-1)).toMatchObject({ parts: "alpha=0 beta=1", complete: "true" });
	});
});
