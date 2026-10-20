import cookiesModule from "@mod/cookies/module";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Session, sessions } from "@mod/session";
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

async function boot() {
	const simulated = simulatedStore();
	const closer = { failing: false, calls: 0 };
	const participant = defineModule({ name: "closer" }, (m) => [
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
			sessionLifecycle,
			sessionRequirements,
			sessionParticipants,
			cookiesModule,
			wiring,
			subjectRevocationStandIn,
			simulated.module,
			participant,
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
		const facts = { subject: "alice", amr: ["pwd"], authenticatedAt: runtime.clock.now() };
		return pair((await s.complete(testRequest(), facts)).cookies[0]);
	};
	const handleOf = async (cookie: string) => ((await s.enter(withCookie(cookie))) as Session).id;
	return { s, simulated, closer, login, handleOf };
}

it("keeps a closed session closed through a lost answer and a failover, and fails closed when the store cannot tell", async () => {
	const { s, simulated, login, handleOf } = await boot();
	const cookie = await login();
	const handle = await handleOf(cookie);
	simulated.beforeNext("replaceIf", "session-store.sessions", async () =>
		simulated.loseNextReply(),
	);
	expect((await s.close(handle)).kind).toBe("closed");
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
	simulated.beforeNext("replaceIf", "session-store.sessions", async () =>
		simulated.stallReplicas(true),
	);
	const raised = await s.raise(withCookie(cookie), ["otp"]);
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
