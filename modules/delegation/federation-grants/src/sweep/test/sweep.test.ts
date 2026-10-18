import type { AuditRecord } from "@mod/audit";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import type { Seal } from "@mod/seal";
import { expect, it } from "vitest";
import { memoryStores } from "../../../test/stores.ts";
import { type Grant, type Judge, recordsWith } from "../../grant/grant.ts";
import { sweepWith } from "../sweep.ts";

const day = 86_400_000;
/** A seal that keeps what it seals in sight, under its context. */
const seal: Seal = {
	seal: (plain, context) => JSON.stringify([context, plain]),
	open: (sealed, context) => {
		const [bound, plain] = JSON.parse(sealed) as [string, string];
		return bound === context ? { kind: "opened", plain } : { kind: "refused" };
	},
};

/** A sweep over memory stores on a test clock, its subjects' revocations as the test sets them. */
async function swept() {
	let now = 1_800_000_000_000;
	const stores = memoryStores(() => now);
	const records = recordsWith(seal);
	const logged = recordingLog();
	const runtime = quietRuntime({ clock: { now: () => now }, log: logged.log });
	const revoked = new Set<string>();
	const judged: string[] = [];
	const judge: Judge = {
		revoked: async (grant) => {
			judged.push(grant.id);
			return revoked.has(grant.subject);
		},
		intentRevoked: async () => false,
		endOf: (grant) => grant.expiresAt,
	};
	const events: AuditRecord[] = [];
	const sweep = sweepWith({
		grants: stores.grants,
		records,
		judge,
		audit: { record: (event) => void events.push(event), lost: () => ({}) },
		...runtime,
	});
	/** Keeps an active grant with credentials, ending in `life` ms. */
	const kept = async (id: string, subject: string, life: number) => {
		const grant: Grant = {
			format: 1,
			id,
			client: "worker",
			subject,
			connection: "cal",
			status: "active",
			createdAt: now,
			scopes: ["openid"],
			authorizedAt: now,
			expiresAt: now + life,
			version: `v-${id}`,
			rotations: { from: now, count: 0 },
		};
		const sealed = records.seal(grant, {
			accessToken: "up",
			tokenType: "Bearer",
			refreshToken: "up-refresh",
			expiresAt: now + 300_000,
			obtainedAt: now,
			scope: ["openid"],
		});
		await stores.grants.create(id, records.stored({ ...grant, sealed }), 30 * day);
	};
	const read = async (id: string) => records.grantOf(await stores.grants.read(id));
	return {
		stores,
		kept,
		read,
		revoked,
		judged,
		events,
		logs: () => logged.lines(),
		run: (signal = new AbortController().signal) => sweep(signal),
		advance: (ms: number) => {
			now += ms;
		},
	};
}

it("erases the credentials of a grant past its end that no request reads, under a new version", async () => {
	const s = await swept();
	await s.kept("ended", "amy", 1000);
	await s.kept("living", "amy", day);
	s.advance(1000);
	await s.run();
	const ended = await s.read("ended");
	expect([ended?.sealed, ended?.status, ended?.version === "v-ended"]).toEqual([
		undefined,
		"active",
		false,
	]);
	expect((await s.read("living"))?.sealed).toBeDefined();
});

it("revokes a grant its subject's revocation ends, though its listing missed it, and records it", async () => {
	const s = await swept();
	await s.kept("missed", "bob", day);
	await s.kept("other", "cy", day);
	s.revoked.add("bob");
	await s.run();
	const missed = await s.read("missed");
	expect([missed?.status, missed?.reason, missed?.sealed]).toEqual([
		"revoked",
		"backstop",
		undefined,
	]);
	expect((await s.read("other"))?.status).toBe("active");
	expect(s.events).toEqual([
		expect.objectContaining({
			kind: "federation.grant.revoked",
			subject: "bob",
			attributes: { client: "worker", connection: "cal", outcome: "backstop" },
		}),
	]);
});

it("passes over a grant with no credentials, judging nothing of it", async () => {
	const s = await swept();
	await s.kept("g", "dee", day);
	s.revoked.add("dee");
	await s.run();
	s.judged.length = 0;
	await s.run();
	expect(s.judged).toEqual([]);
});

it("writes no revocation over a grant authorized again since it was judged, judging it once more first", async () => {
	const s = await swept();
	await s.kept("g", "eve", day);
	s.revoked.add("eve");
	// Authorized again between the judgement and the write, as a renewal's activation writes it.
	s.stores.raceNext((record) => ({ ...(record as object), authorizedAt: 1 }) as never);
	await s.run();
	const g = await s.read("g");
	expect(s.judged).toEqual(["g", "g"]);
	expect([g?.status, g?.authorizedAt]).toEqual(["revoked", 1]);
});

it("stops a pass at a page it cannot read, logging it, and the next pass goes over every grant", async () => {
	const s = await swept();
	await s.kept("a", "fay", 1000);
	await s.kept("b", "fay", 1000);
	s.advance(1000);
	s.stores.down.failNext("scan");
	await s.run();
	expect(s.logs().map((line) => line.event)).toContain("federation-grants.sweep_incomplete");
	expect((await s.read("a"))?.sealed).toBeDefined();
	await s.run();
	expect([(await s.read("a"))?.sealed, (await s.read("b"))?.sealed]).toEqual([
		undefined,
		undefined,
	]);
});

it("goes on past a grant it cannot sweep, counting it, and stops at the stop signal", async () => {
	const s = await swept();
	await s.kept("a", "gus", 1000);
	await s.kept("b", "gus", 1000);
	s.advance(1000);
	s.stores.down.failNext("read");
	await s.run();
	expect(s.logs()).toContainEqual(
		expect.objectContaining({ event: "federation-grants.sweep_failed", fields: { count: 1 } }),
	);
	expect((await s.read("b"))?.sealed).toBeUndefined();
	const stop = new AbortController();
	stop.abort();
	await s.kept("c", "gus", 0);
	await s.run(stop.signal);
	expect((await s.read("c"))?.sealed).toBeDefined();
});
