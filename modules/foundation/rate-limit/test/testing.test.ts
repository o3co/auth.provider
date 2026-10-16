import { auditStandIn } from "@mod/audit/testing";
import { listening, routes, use } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { type Assembly, assemble, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import {
	attemptLimit,
	attemptsPerSource,
	type LockoutPolicy,
	lockouts,
	rateLimit,
	requestsPerSource,
} from "../src/contract.ts";
import rateLimitModule from "../src/module.ts";
import { rateLimitStandIn } from "../src/testing.ts";

const start = 1_800_000_000_000;
let now = start;
const runtime = quietRuntime({
	clock: { now: () => now },
	random: { bytes: (n) => new Uint8Array(n) },
});

/** Runs the same calls on the real module and on the stand-in alone, from the same instant. */
async function both<T>(run: (app: Assembly) => Promise<T>): Promise<T[]> {
	const compositions: Module[][] = [
		[rateLimitModule, simulatedStore().module, auditStandIn().module],
		[rateLimitStandIn],
	];
	const answers: T[] = [];
	for (const modules of compositions) {
		now = start;
		answers.push(await run(await assemble({ modules, config: kernelConfig(), runtime })));
	}
	return answers;
}

it("counts rate limits and attempts as the real module does, apart from each other, with no store", async () => {
	const [real, standIn] = await both(async (app) => {
		const seen: unknown[] = [];
		const window = { limit: 2, ms: 60_000 };
		for (const limit of [app.get(rateLimit), app.get(attemptLimit), app.get(rateLimit)]) {
			for (const key of ["a", "a", "a", "b"]) seen.push(await limit.hit("w", key, window));
			now += 20_000;
		}
		now += 60_000;
		seen.push(await app.get(rateLimit).hit("w", "a", window));
		seen.push(await app.get(rateLimit).hit("w", "c", { limit: 0, ms: 500 }));
		return seen;
	});
	expect(standIn).toEqual(real);
	expect(real?.filter((answer) => (answer as { kind: string }).kind === "limited")).toHaveLength(6);
});

it("holds, reserves, hands back and releases lockouts, under terms too, as the real module does", async () => {
	const policy: LockoutPolicy = {
		threshold: 2,
		backoffMs: 1000,
		maxBackoffMs: 4000,
		budget: 4,
		budgetWindowMs: 600_000,
		hardLimit: 6,
		memoryMs: 60_000,
	};
	const [real, standIn] = await both(async (app) => {
		const l = app.get(lockouts);
		const seen: unknown[] = [];
		const step = async (answer: Promise<unknown>, ms = 0) => {
			seen.push((await answer) ?? null);
			now += ms;
		};
		await step(l.failed("n", "k", policy));
		await step(l.failed("n", "k", policy));
		await step(l.check("n", "k", policy), 1001);
		const reserved = await l.reserve("n", "k", policy);
		seen.push(reserved);
		const held = await l.reserve("n", "k", policy);
		seen.push(held);
		now += 2001;
		const reservation = reserved.kind === "open" ? reserved.reservation : -1;
		await step(l.abandoned("n", "k", policy, reservation));
		await step(l.check("n", "k", policy));
		await step(l.succeeded("n", "k", policy));
		await step(l.failed("n", "k", policy), 61_000);
		await step(l.failed("n", "k", policy));
		for (let i = 0; i < 4; i++) await step(l.failed("n", "hard", policy), 5000);
		await step(l.failed("n", "hard", policy), 5000);
		await step(l.failed("n", "hard", policy), 700_000);
		await step(l.check("n", "hard", policy));
		await step(l.releaseUnder("n", "hard", policy, { kind: "whole" }));
		await step(l.check("n", "hard", policy));
		for (let i = 0; i < 6; i++) await step(l.failed("n", "terms", policy));
		const read = await l.standing("n", "terms", policy);
		seen.push(read);
		const terms = { kind: "checked", once: { id: "i", keepMs: 1000 }, forgive: read } as const;
		await step(
			l.releaseUnder("n", "terms", policy, { ...terms, lift: { fixedAt: read.fixedAt ?? 0 } }),
		);
		await step(l.releaseUnder("n", "terms", policy, terms), 1001);
		await step(l.releaseUnder("n", "terms", policy, terms));
		await step(l.releaseUnder("n", "terms", policy, { kind: "whole" }));
		return seen;
	});
	expect(standIn).toEqual(real);
	const holds = (real ?? []).map((answer) => (answer as { hold?: string } | null)?.hold);
	expect(holds).toEqual(expect.arrayContaining(["backoff", "budget", "hard"]));
});

it("offers both per-source policies, answering as the real ones do, with no store and no audit", async () => {
	const window = { limit: 1, ms: 60_000 };
	const routed = defineModule({ name: "routed" }, (m) => [
		m.contribute(routes).by(() => ({
			method: "GET",
			path: "/requests",
			uses: [use(requestsPerSource, { name: "test", window })],
			handle: () => ({ status: 204 }),
		})),
		m.contribute(routes).by(() => ({
			method: "GET",
			path: "/attempts",
			uses: [use(attemptsPerSource, { name: "test", window })],
			handle: () => ({ status: 204 }),
		})),
	]);
	const app = await assemble({
		modules: [http, rateLimitStandIn, routed],
		config: { ...kernelConfig(), ...httpConfig({ "trusted-proxies": ["127.0.0.1"] }) },
		runtime,
	});
	await app.start();
	try {
		const from = async (path: string, address?: string) => {
			const answer = await fetch(`http://127.0.0.1:${app.get(listening).port()}${path}`, {
				headers: address ? { "x-forwarded-for": address } : {},
			});
			const body = answer.status === 204 ? undefined : await answer.json();
			return [answer.status, answer.headers.get("retry-after"), body];
		};
		expect(await from("/requests", "2001:db8::1")).toEqual([204, null, undefined]);
		expect(await from("/requests", "2001:db8::2")).toEqual([429, "60", { error: "rate_limited" }]);
		expect(await from("/attempts", "2001:db8::1")).toEqual([204, null, undefined]);
		expect(await from("/attempts", "2001:db8::1")).toEqual([
			429,
			"60",
			{ error: "too_many_attempts" },
		]);
		expect(await from("/attempts", "198.51.100.1")).toEqual([204, null, undefined]);
		expect(await from("/requests")).toEqual([503, null, { error: "service_unavailable" }]);
	} finally {
		await app.stop(1000);
	}
});
