import { audit } from "@mod/audit";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { flowParts } from "@mod/mfa-flows";
import { factorManaging } from "@mod/mfa-managing";
import { factorReading } from "@mod/mfa-reading";
import { lockouts } from "@mod/rate-limit";
import { revocations } from "@mod/subject-revocation";
import { expect, it } from "vitest";
import { mfaReset, resetCandidates, resetParts } from "../src/contract.ts";
import resetModule from "../src/module.ts";

it("resets over the contracts it is given, releasing mfa-flows' lockout by its name and policy", async () => {
	const released: unknown[] = [];
	const policy = { budget: 10 };
	const parts = defineModule({ name: "parts", takes: [] }, (m) => [
		m.provide(flowParts).by(() => ({ lockout: { name: "mfa", policy } }) as never),
		m
			.provide(factorManaging)
			.by(() => ({ clear: async () => ({ count: 1, kinds: ["code"] }) }) as never),
		m.provide(revocations).by(() => ({ record: async () => ({ complete: true }) }) as never),
		m.provide(lockouts).by(
			() =>
				({
					releaseUnder: async (name: string, _key: string, given: unknown) => {
						released.push([name, given === policy]);
						return {};
					},
				}) as never,
		),
		m.provide(audit).by(() => ({ record: () => {}, lost: () => ({}) })),
		m.provide(factorReading).by(() => ({ unclaimedWritten: async () => 0 }) as never),
	]);
	const app = await assemble({ modules: [parts, resetModule], config: kernelConfig() });
	expect(await app.get(mfaReset).run("ann")).toMatchObject({ kind: "done", removed: 1 });
	expect(released).toEqual([["mfa", true]]);
});

it("refuses two parts of one name, and calls a part composed", async () => {
	const base = defineModule({ name: "base", takes: [] }, (m) => [
		m.provide(flowParts).by(() => ({ lockout: { name: "mfa", policy: { budget: 10 } } }) as never),
		m.provide(factorManaging).by(() => ({ clear: async () => ({ count: 0, kinds: [] }) }) as never),
		m.provide(revocations).by(() => ({ record: async () => ({ complete: true }) }) as never),
		m.provide(lockouts).by(() => ({ releaseUnder: async () => ({}) }) as never),
		m.provide(audit).by(() => ({ record: () => {}, lost: () => ({}) })),
		m.provide(factorReading).by(() => ({ unclaimedWritten: async () => 0 }) as never),
	]);
	const removed: string[] = [];
	const part = (module: string, name: string) =>
		defineModule({ name: module, takes: [] }, (m) => [
			m.contribute(resetParts).by(() => ({
				name,
				remove: async (subject: string) => {
					removed.push(`${module} ${subject}`);
					return { kind: "done", removed: 1 } as const;
				},
			})),
		]);
	const app = await assemble({
		modules: [base, resetModule, part("one", "things")],
		config: kernelConfig(),
	});
	expect(await app.get(mfaReset).run("ann")).toMatchObject({ kind: "done", parts: { things: 1 } });
	expect(removed).toEqual(["one ann"]);
	await expect(
		assemble({
			modules: [base, resetModule, part("one", "things"), part("two", "things")],
			config: kernelConfig(),
		}),
	).rejects.toThrow();
});

it("tells how many of a subject's counting factors are written and stand for nothing, as mfa reads them", async () => {
	const asked: string[] = [];
	const base = defineModule({ name: "base", takes: [] }, (m) => [
		m.provide(flowParts).by(() => ({ lockout: { name: "mfa", policy: { budget: 10 } } }) as never),
		m.provide(factorManaging).by(() => ({ clear: async () => ({ count: 0, kinds: [] }) }) as never),
		m.provide(revocations).by(() => ({ record: async () => ({ complete: true }) }) as never),
		m.provide(lockouts).by(() => ({ releaseUnder: async () => ({}) }) as never),
		m.provide(audit).by(() => ({ record: () => {}, lost: () => ({}) })),
		m.provide(factorReading).by(
			() =>
				({
					unclaimedWritten: async (subject: string) => {
						asked.push(subject);
						return subject === "ann" ? 2 : 0;
					},
				}) as never,
		),
	]);
	const app = await assemble({ modules: [base, resetModule], config: kernelConfig() });
	expect(await app.get(resetCandidates).unclaimed("ann")).toBe(2);
	expect(await app.get(resetCandidates).unclaimed("bob")).toBe(0);
	expect(asked).toEqual(["ann", "bob"]);
});
