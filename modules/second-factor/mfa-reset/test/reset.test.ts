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
	} = {},
) => {
	const calls: string[] = [];
	const events: AuditRecord[] = [];
	const logged = recordingLog();
	const records = [...(script.records ?? [])];
	const reset = resetOver({
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
