import cookiesModule from "@mod/cookies/module";
import { type Eraser, erasers } from "@mod/erasure-extensions";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import httpServer from "@mod/http-server/module";
import { assemble, contract, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Session, sessions } from "@mod/session";
import { openedOf } from "@mod/session/testing";
import sessionLifecycle from "@mod/session-lifecycle/module";
import { sessionLifecycleConfig } from "@mod/session-lifecycle/testing";
import { participants } from "@mod/session-participants";
import sessionParticipants from "@mod/session-participants/module";
import sessionRequirements from "@mod/session-requirements/module";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime();
const pair = (setCookie: string | undefined) => setCookie?.split(";")[0] ?? "";
const withCookie = (cookie: string) =>
	testRequest({ headers: new Map([["cookie", cookie]]), source: { scheme: "https" } });

const collected = contract<readonly Eraser[]>("test.erasers");

async function boot(phase: "reader" | "indexed" = "reader") {
	const simulated = simulatedStore();
	if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
	const closer = { failing: false, calls: 0 };
	const participant = defineModule({ name: "closer", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(participants).by(() => ({
			name: "closer",
			closing: async () => {
				closer.calls++;
				if (closer.failing) throw new Error("not yet");
			},
		})),
	]);
	const app = await assemble({
		modules: [
			http,
			httpServer,
			sessionLifecycle,
			sessionRequirements,
			sessionParticipants,
			cookiesModule,
			wiring,
			subjectRevocationStandIn,
			simulated.module,
			participant,
			defineModule({ name: "eraser-reader", replicaSafe: false, takes: [erasers] }, (m) => [
				m.provide(collected).by(async (c) => c.collect(erasers)),
			]),
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			...sessionLifecycleConfig({ lifetime: "1m" }),
		},
		runtime,
	});
	const s = app.get(sessions);
	const login = async () => {
		const facts = {
			subject: "alice",
			amr: ["pwd"],
			authenticatedAt: runtime.clock.now(),
			provenSince: runtime.clock.now(),
		};
		return pair(openedOf(await s.open(testRequest(), facts)).cookies[0]);
	};
	const handleOf = async (cookie: string) => ((await s.enter(withCookie(cookie))) as Session).id;
	const eraser = () => app.get(collected).find((e) => e.name === "session-lifecycle") as Eraser;
	return { s, simulated, closer, login, handleOf, eraser };
}

it("keeps a closed session closed through a lost answer and a failover, and fails closed when the store cannot tell", async () => {
	const { s, simulated, login, handleOf } = await boot();
	const cookie = await login();
	const handle = await handleOf(cookie);
	// A raw record's change is a batch on its own partition.
	let lost = false;
	simulated.beforeNext("batch", "session-store.sessions", async () => {
		lost = true;
		simulated.loseNextReply();
	});
	expect((await s.close(handle)).kind).toBe("closed");
	expect(lost).toBe(true);
	await simulated.failover();
	expect(await s.enter(withCookie(cookie))).toBeUndefined();
	expect((await s.entryOf(handle)).kind).toBe("absent");
	simulated.unreachable(true);
	await expect(s.enter(withCookie(cookie))).rejects.toThrow();
});

it("retires the old cookie of a raise through a lost answer or a failed send, for good", async () => {
	const { s, simulated, login } = await boot();
	for (const fault of ["took effect", "not applied"]) {
		const cookie = await login();
		if (fault === "not applied") simulated.failNext("take");
		else
			simulated.beforeNext("take", "session-store.cookies", async () => simulated.loseNextReply());
		const raised = await s.raise(withCookie(cookie), ["otp"]);
		expect(raised?.raised).toBe(true);
		await simulated.failover();
		expect(await s.enter(withCookie(cookie))).toBeUndefined();
		const fresh = withCookie(pair(raised?.cookies[0]));
		expect((await s.enter(fresh))?.context.amr).toEqual(["pwd", "otp"]);
	}
});

it("keeps a closing until its participants are done, however far the store clock runs", async () => {
	const { s, simulated, closer, login, handleOf } = await boot();
	const handle = await handleOf(await login());
	closer.failing = true;
	expect((await s.close(handle)).kind).toBe("pending");
	simulated.shiftClock(10 * 365 * 86_400_000);
	closer.failing = false;
	const calls = closer.calls;
	expect((await s.close(handle)).kind).toBe("closed");
	expect(closer.calls).toBe(calls + 1);
});

it("never lets a raise it could not confirm be seen: what an entry reads is what a failover keeps", async () => {
	const { s, simulated, login } = await boot();
	const cookie = await login();
	// The raise's record write applies on the primary, but its confirmation never comes.
	let stalled = false;
	simulated.beforeNext("batch", "session-store.sessions", async () => {
		stalled = true;
		simulated.stallReplicas(true);
	});
	const raised = await s.raise(withCookie(cookie), ["otp"]);
	expect(stalled).toBe(true);
	expect(raised?.raised).toBe(false);
	const fresh = withCookie(pair(raised?.cookies[0]));
	const seen = await s.enter(fresh).catch((error) => error);
	expect(isUnavailable(seen) || !(seen as Session | undefined)?.context.amr.includes("otp")).toBe(
		true,
	);
	simulated.stallReplicas(false);
	const settled = (await s.enter(fresh))?.context.amr ?? [];
	await simulated.failover();
	expect((await s.enter(fresh))?.context.amr ?? []).toEqual(settled);
}, 30_000);

it("erases an indexed subject's sessions and listing end to end, counting the open session removed as a logout gap", async () => {
	const { s, closer, login, handleOf, eraser } = await boot("indexed");
	const [open, closed] = [await handleOf(await login()), await handleOf(await login())];
	expect((await s.close(closed)).kind).toBe("closed");
	expect(eraser().erasable).toBe(true);
	const { reports, logoutGaps } = await eraser().online("alice", new AbortController().signal);
	expect(reports).toMatchObject([
		{ kind: "erased", space: "session-store.sessions", removed: 2 },
		{ kind: "erased", space: "session-store.subjects" },
	]);
	expect(logoutGaps).toBe(1);
	expect(await s.subjectOf?.(open)).toBeUndefined();
	// Its subject erased, a close finds no record, writes nothing and calls no participant.
	const calls = closer.calls;
	expect((await s.close(open)).kind).toBe("closed");
	expect(closer.calls).toBe(calls);
	await expect(login()).rejects.toSatisfy(isUnavailable);
});
