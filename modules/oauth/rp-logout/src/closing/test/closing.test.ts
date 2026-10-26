import type { AuditRecord } from "@mod/audit";
import { testRequest } from "@mod/http/testing";
import { Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import type { CloseOutcome } from "@mod/session";
import { describe, expect, it } from "vitest";
import { closingOver } from "../closing.ts";

/** The parts a close takes, each answering as given and keeping the order it was asked in. */
function parts(close: () => Promise<CloseOutcome>) {
	const asked: string[] = [];
	const recorded: AuditRecord[] = [];
	const logged = recordingLog();
	const closing = closingOver({
		clients: {
			find: async (id) => {
				asked.push(`client ${id}`);
				throw new Unavailable("clients");
			},
		},
		sessions: {
			close: async () => {
				asked.push("close");
				return close();
			},
		},
		sessionClients: {
			members: async () => {
				asked.push("members");
				return [{ member: "app", remainingMs: 60_000 }];
			},
		},
		upstream: {
			name: "upstream",
			at: async () => {
				asked.push("upstream");
				return "https://idp.example/end";
			},
		},
		audit: { record: (e) => void recorded.push(e) },
		log: logged.log,
	});
	return { closing, asked, recorded, logged };
}

const request = testRequest({
	method: "POST",
	path: "/oauth/logout",
	headers: new Map([["user-agent", "ua/1"]]),
});
const session = { id: "s1", subject: "alice" };

describe("a logout's close, the same whichever route asked it", () => {
	it("reads the session's clients and the upstream's end before the close, and records the logout", async () => {
		const { closing, asked, recorded } = parts(async () => ({
			kind: "closed",
			cookies: ["c"],
			session,
			from: "open",
		}));
		const closed = await closing(request, { sid: "s1", back: {} });
		expect(asked).toEqual(["members", "upstream", "close"]);
		expect(closed).toMatchObject({
			kind: "logged-out",
			cookies: ["c"],
			upstream: "https://idp.example/end",
		});
		expect(recorded.map((e) => [e.kind, e.subject, e.attributes])).toEqual([
			["logout.success", "alice", { sid: "s1", source: "127.0.0.1", userAgent: "ua/1" }],
		]);
	});

	it("leaves out a frame whose client cannot be read, logged", async () => {
		const { closing, logged } = parts(async () => ({
			kind: "closed",
			cookies: [],
			session,
			from: "open",
		}));
		const closed = await closing(request, { sid: "s1", back: {} });
		if (closed.kind !== "logged-out") throw new Error(closed.kind);
		expect(await closed.frames()).toEqual([]);
		expect(logged.lines().map((l) => l.event)).toContain("rp-logout.client_unavailable");
	});

	it("is no logout of its own for a session closed before or gone, recording nothing", async () => {
		for (const outcome of [
			{ kind: "closed", cookies: ["c"], session, from: "closed" },
			{ kind: "closed", cookies: ["c"] },
		] as const) {
			const { closing, recorded } = parts(async () => outcome);
			expect(await closing(request, { sid: "s1", back: {} })).toEqual({
				kind: "not-this-logout",
				cookies: ["c"],
			});
			expect(recorded).toEqual([]);
		}
	});

	it("is pending, recorded by its sid and source, where the close is left for later", async () => {
		const { closing, recorded } = parts(async () => ({
			kind: "pending",
			cookies: ["c"],
			session,
			from: "open",
		}));
		expect(await closing(request, { sid: "s1", back: {} })).toEqual({
			kind: "pending",
			cookies: ["c"],
		});
		expect(recorded.map((e) => [e.kind, e.subject, e.attributes])).toEqual([
			["logout.close_pending", "alice", { sid: "s1", source: "127.0.0.1" }],
		]);
	});

	it("is unavailable, the failed close recorded, where the session cannot be closed", async () => {
		const { closing, recorded } = parts(async () => {
			throw new Unavailable("session");
		});
		expect(await closing(request, { sid: "s1", subject: "alice", back: {} })).toEqual({
			kind: "unavailable",
		});
		expect(recorded.map((e) => [e.kind, e.subject, e.attributes])).toEqual([
			[
				"logout.cascade_failed",
				"alice",
				{ sid: "s1", source: "127.0.0.1", userAgent: "ua/1", store: "session" },
			],
		]);
	});
});
