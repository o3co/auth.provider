import type { AuditRecord } from "@mod/audit";
import { testRequest } from "@mod/http/testing";
import { Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import type { Counted, RateLimit, Window } from "@mod/rate-limit";
import { addressesOf } from "@mod/request-source";
import { describe, expect, it } from "vitest";
import { endpointOf } from "../src/endpoint.ts";

const current = "Kq3vX9pLm2Rt7Yw4Nc8Bz1Hd6Fj0Gs5Ua-Ve_Io2LxM";
const previous = "Wn5Tb8Qr1Ms4Kd7Hf0Jg3Lc6Pz9Xv2Yu-Ea_Ri5OkPq";
const inside = "198.51.100.7";
const outside = "203.0.113.9";

/** A window counted in memory, refusing past its limit; `down` makes it unable to count. */
function windowCounter() {
	const counts = new Map<string, number>();
	const state = { down: false };
	const keys: string[] = [];
	const limit: RateLimit = {
		hit: async (name: string, key: string, window: Window): Promise<Counted> => {
			if (state.down) throw new Unavailable("rate-limit");
			keys.push(key);
			const count = (counts.get(`${name}/${key}`) ?? 0) + 1;
			counts.set(`${name}/${key}`, count);
			return count > window.limit ? { kind: "limited", retryAfterMs: 30_000 } : { kind: "allowed" };
		},
	};
	return { limit, state, keys };
}

/** Request headers that note each name read. */
class NotedHeaders extends Map<string, string> {
	readonly read: string[] = [];
	override get(name: string) {
		this.read.push(name);
		return super.get(name);
	}
}

/** The endpoint over fakes: recordings of what it records, and switches for what fails. */
function harness(
	options: {
		readonly previous?: boolean;
		readonly failures?: number;
		readonly requests?: number;
	} = {},
) {
	const failures = windowCounter();
	const requests = windowCounter();
	const recorded: AuditRecord[] = [];
	const revoked: { subject: string; keepDelegations: boolean | undefined }[] = [];
	const recording = { answer: "complete" as "complete" | "incomplete" | "unknown" | "broken" };
	const logged = recordingLog();
	// Notes each credential the endpoint reads, so a comparison that stops early shows.
	const compared: number[] = [];
	const credentials = new Proxy(options.previous ? [current, previous] : [current], {
		get: (target, key, receiver) => {
			if (typeof key === "string" && /^\d+$/.test(key)) compared.push(Number(key));
			return Reflect.get(target, key, receiver);
		},
	});
	const endpoint = endpointOf({
		credentials,
		sources: addressesOf([`${inside}/32`, "2001:db8:1::/48"]),
		failures: { limit: failures.limit, window: { limit: options.failures ?? 10, ms: 60_000 } },
		requests: { limit: requests.limit, window: { limit: options.requests ?? 100, ms: 60_000 } },
		revocations: {
			record: async (subject, given) => {
				revoked.push({ subject, keepDelegations: given?.keepDelegations });
				if (recording.answer === "unknown") throw new Unavailable("subject-revocation");
				if (recording.answer === "broken") throw new Error("broken");
				return { complete: recording.answer === "complete" };
			},
		},
		recorded: { record: (event) => recorded.push(event) },
		log: logged.log,
	});
	const send = async (
		parts: {
			readonly credential?: string | null;
			readonly authorization?: string;
			readonly json?: Record<string, unknown>;
			readonly address?: string;
			readonly scheme?: "http" | "https";
			readonly determined?: boolean;
		} = {},
	) => {
		const credential = parts.credential === undefined ? current : parts.credential;
		const authorization =
			parts.authorization ?? (credential === null ? undefined : `Bearer ${credential}`);
		const request = testRequest({
			method: "POST",
			path: "/ledger/subject-revocations",
			json: parts.json ?? { subject: "alice" },
			source: {
				address: parts.address ?? inside,
				scheme: parts.scheme ?? "https",
				determined: parts.determined ?? true,
			},
		});
		const headers = new NotedHeaders(
			authorization === undefined ? [] : [["authorization", authorization]],
		);
		const answer = await endpoint({ ...request, headers });
		const body = answer.body as { json: unknown } | undefined;
		return {
			status: answer.status,
			headers: answer.headers ?? {},
			json: body?.json,
			read: headers.read,
		};
	};
	return { send, failures, requests, recorded, revoked, recording, logged, compared };
}

const denied = (reason: string, source: string) => ({
	kind: "subject.revocation.denied",
	attributes: { reason, source },
});

describe("checking a request in order", () => {
	it("refuses a request that did not come over https before reading its credential, counting and recording nothing", async () => {
		const { send, failures, requests, recorded, revoked, compared } = harness();
		for (const credential of [current, "wrong", null]) {
			const answer = await send({ credential, scheme: "http" });
			expect([answer.status, answer.json, answer.read]).toEqual([
				403,
				{ error: "https_required" },
				[],
			]);
		}
		// Not recorded, so one sending in plain http cannot flood the audit.
		expect([failures.keys, requests.keys, revoked, recorded, compared]).toEqual([
			[],
			[],
			[],
			[],
			[],
		]);
	});

	it("refuses a source outside sources alike whatever the credential, counting each as a failure", async () => {
		const { send, failures, recorded, revoked } = harness();
		for (const credential of [current, "wrong", null]) {
			const answer = await send({ credential, address: outside });
			expect([answer.status, answer.json, answer.headers["www-authenticate"]]).toEqual([
				403,
				{ error: "forbidden_source" },
				undefined,
			]);
		}
		expect(revoked).toEqual([]);
		expect(failures.keys).toEqual([outside, outside, outside]);
		expect(recorded.at(-1)).toEqual(denied("forbidden_source", outside));
	});

	it("refuses an undetermined source, counting its failures under the proxy that sent it", async () => {
		const { send, failures, recorded, revoked } = harness();
		const proxy = "192.0.2.1";
		const answer = await send({ address: proxy, determined: false });
		expect([answer.status, answer.json]).toEqual([403, { error: "forbidden_source" }]);
		expect([failures.keys, revoked]).toEqual([[proxy], []]);
		expect(recorded).toEqual([denied("forbidden_source", proxy)]);
		// Not even a proxy at a listed address stands for the ledger.
		expect((await send({ address: inside, determined: false })).status).toBe(403);
	});

	it("answers a missing and a wrong credential from inside alike, with a Bearer challenge", async () => {
		const { send, failures, revoked, recorded } = harness();
		const answers = [];
		for (const parts of [
			{ credential: null },
			{ credential: "wrong" },
			{ credential: `${current}x` },
			{ authorization: `Basic ${current}` },
			{ authorization: "Bearer" },
		]) {
			const answer = await send(parts);
			answers.push([answer.status, answer.json, answer.headers["www-authenticate"]]);
		}
		expect(new Set(answers.map((a) => JSON.stringify(a)))).toEqual(
			new Set([JSON.stringify([401, { error: "unauthenticated" }, "Bearer"])]),
		);
		expect([failures.keys.length, revoked]).toEqual([5, []]);
		expect(recorded).toEqual(Array(5).fill(denied("unauthenticated", inside)));
	});

	it("takes the current credential, and the previous one only while it is set, comparing both each time", async () => {
		const both = harness({ previous: true });
		expect((await both.send({ credential: current })).status).toBe(200);
		expect(both.compared).toEqual([0, 1]);
		expect((await both.send({ credential: previous })).status).toBe(200);
		expect((await both.send({ credential: "wrong" })).status).toBe(401);
		expect(both.compared).toEqual([0, 1, 0, 1, 0, 1]);
		const one = harness();
		expect((await one.send({ credential: current })).status).toBe(200);
		expect((await one.send({ credential: previous })).status).toBe(401);
	});

	it("takes the scheme's name in any case, as RFC 7235 reads it", async () => {
		const { send } = harness();
		expect((await send({ authorization: `bearer ${current}` })).status).toBe(200);
	});

	it("keys an IPv6 source by its /64, in both windows", async () => {
		const { send, requests, failures } = harness();
		expect((await send({ address: "2001:db8:1:2::9" })).status).toBe(200);
		expect(requests.keys).toEqual(["2001:db8:1:2::/64"]);
		expect((await send({ address: "2001:db8:1:2::a", credential: "wrong" })).status).toBe(401);
		expect((await send({ address: "2001:db9::1" })).status).toBe(403);
		expect(failures.keys).toEqual(["2001:db8:1:2::/64", "2001:db9:0:0::/64"]);
	});
});

describe("the two windows", () => {
	it("lets an authenticated request through however full the failure window is", async () => {
		const { send } = harness({ failures: 2 });
		const failed = [];
		for (let i = 0; i < 3; i++) failed.push((await send({ credential: "wrong" })).status);
		expect(failed).toEqual([401, 401, 429]);
		expect((await send()).status).toBe(200);
	});

	it("answers a failure past the failure window 429 with the wait, recording no more", async () => {
		const { send, recorded } = harness({ failures: 2 });
		await send({ credential: "wrong" });
		expect((await send({ address: outside })).status).toBe(403);
		expect((await send({ address: outside })).status).toBe(403);
		const answer = await send({ address: outside });
		expect([answer.status, answer.json, answer.headers["retry-after"]]).toEqual([
			429,
			{ error: "rate_limited" },
			"30",
		]);
		// The failures that filled the window were recorded; the requests past it are not, so they cannot flood the audit.
		expect(recorded).toEqual([
			denied("unauthenticated", inside),
			denied("forbidden_source", outside),
			denied("forbidden_source", outside),
		]);
		expect((await send({ address: outside })).status).toBe(429);
		expect(recorded).toHaveLength(3);
	});

	it("counts authenticated requests in the request window, past it 429, before reading the body", async () => {
		const { send, revoked, recorded } = harness({ requests: 3 });
		for (let i = 0; i < 3; i++) expect((await send()).status).toBe(200);
		const answer = await send({ json: { subject: "" } });
		expect([answer.status, answer.json, answer.headers["retry-after"]]).toEqual([
			429,
			{ error: "rate_limited" },
			"30",
		]);
		expect(revoked).toHaveLength(3);
		expect(recorded.map((e) => e.kind)).toEqual(Array(3).fill("subject.revocation.requested"));
	});

	it("refuses with 503 when either window cannot count, recorded as such", async () => {
		const { send, failures, requests, recorded, revoked } = harness();
		failures.state.down = true;
		const failed = await send({ credential: "wrong" });
		expect([failed.status, failed.json, failed.headers["retry-after"]]).toEqual([
			503,
			{ error: "temporarily_unavailable" },
			"5",
		]);
		failures.state.down = false;
		requests.state.down = true;
		expect((await send()).status).toBe(503);
		expect(revoked).toEqual([]);
		expect(recorded).toEqual([
			denied("rate_limit_unavailable", inside),
			denied("rate_limit_unavailable", inside),
		]);
	});
});

describe("the body", () => {
	it("refuses a subject that is not one, keeping its value out of the answer and the audit", async () => {
		const { send, revoked, recorded } = harness();
		for (const subject of [
			undefined,
			"",
			7,
			"a".repeat(256),
			"é",
			"a\u0000b",
			"a\nb",
			"a\u007fb",
		]) {
			const answer = await send({ json: { subject } });
			expect([answer.status, answer.json], String(subject)).toEqual([
				400,
				{ error: "invalid_request" },
			]);
		}
		expect(revoked).toEqual([]);
		expect(recorded.every((e) => e.subject === undefined)).toBe(true);
		expect(recorded.at(-1)).toEqual(denied("invalid_request", inside));
	});

	it("ends delegations unless told to keep them, and refuses any other word", async () => {
		const { send, revoked } = harness();
		await send({ json: { subject: "a" } });
		await send({ json: { subject: "b", delegations: "end" } });
		await send({ json: { subject: "c", delegations: "keep" } });
		for (const delegations of ["KEEP", "", null, true, ["keep"]]) {
			const answer = await send({ json: { subject: "d", delegations } });
			expect([answer.status, answer.json]).toEqual([400, { error: "invalid_request" }]);
		}
		expect(revoked).toEqual([
			{ subject: "a", keepDelegations: false },
			{ subject: "b", keepDelegations: false },
			{ subject: "c", keepDelegations: true },
		]);
	});

	it("refuses a member it does not know, so a sender's mistake shows", async () => {
		const { send, revoked, recorded } = harness();
		for (const json of [
			{ subject: "a", keepDelegations: true },
			{ subject: "a", delegations: "keep", reason: "left" },
		]) {
			const answer = await send({ json });
			expect([answer.status, answer.json]).toEqual([400, { error: "invalid_request" }]);
		}
		expect(revoked).toEqual([]);
		expect(recorded.at(-1)).toEqual(denied("invalid_request", inside));
	});

	it("takes the widest subject users does, 255 ASCII characters", async () => {
		const { send, revoked } = harness();
		expect((await send({ json: { subject: "~".repeat(255) } })).status).toBe(200);
		expect(revoked).toHaveLength(1);
	});
});

describe("recording", () => {
	it("answers complete once every follower finished, recorded with the subject and never the credential", async () => {
		const { send, recorded } = harness();
		const answer = await send({ json: { subject: "alice", delegations: "keep" } });
		expect([answer.status, answer.json, answer.headers["cache-control"]]).toEqual([
			200,
			{ complete: true },
			"no-store",
		]);
		expect(recorded).toEqual([
			{
				kind: "subject.revocation.requested",
				subject: "alice",
				attributes: { delegations: "keep", outcome: "complete", source: inside },
			},
		]);
		expect(JSON.stringify(recorded)).not.toContain(current);
	});

	it("answers 503 incomplete when a follower did not finish, and unknown when the boundary is not confirmed, warning of both", async () => {
		const { send, recording, recorded, logged } = harness();
		recording.answer = "incomplete";
		const incomplete = await send();
		recording.answer = "unknown";
		const unknown = await send();
		expect([incomplete, unknown].map((a) => [a.status, a.json, a.headers["retry-after"]])).toEqual([
			[503, { error: "temporarily_unavailable", state: "incomplete" }, "5"],
			[503, { error: "temporarily_unavailable", state: "unknown" }, "5"],
		]);
		expect(recorded.map((e) => e.attributes?.outcome)).toEqual(["incomplete", "unknown"]);
		expect(logged.lines().map((line) => [line.level, line.event])).toEqual([
			["warn", "subject-revocation-http.incomplete"],
			["warn", "subject-revocation-http.unknown"],
		]);
	});

	it("answers a resend as the first, recording it again", async () => {
		const { send, revoked } = harness();
		const first = await send();
		const again = await send();
		expect(again).toEqual(first);
		expect(revoked).toHaveLength(2);
	});

	it("answers 200 for a subject no user holds", async () => {
		const { send } = harness();
		expect((await send({ json: { subject: "nobody-ever" } })).json).toEqual({ complete: true });
	});

	it("records any other failure of recording as failed, and lets it through, so http answers it", async () => {
		const { send, recording, recorded } = harness();
		recording.answer = "broken";
		await expect(send()).rejects.toThrow("broken");
		expect(recorded).toEqual([
			{
				kind: "subject.revocation.requested",
				subject: "alice",
				attributes: { delegations: "end", outcome: "failed", source: inside },
			},
		]);
	});
});
