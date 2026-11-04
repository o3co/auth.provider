import { describe, expect, it } from "vitest";
import {
	assemble,
	BootRefused,
	type BuildContext,
	contract,
	defineModule,
	kernelConfig,
	type Module,
	Unavailable,
} from "../src/contract.ts";
import { quietRuntime } from "../src/testing.ts";
import { refusalsOf } from "./refusals.ts";

const single = kernelConfig();

/** A module whose build registers `hook`, and a stop hook noting its name, if `order` is given. */
const hooking = (
	name: string,
	hook: (c: BuildContext<unknown>) => Promise<void> | void,
	order?: string[],
): Module =>
	defineModule({ name, replicaSafe: true, takes: [] }, (m) => [
		m.provide(contract<void>(name)).by((c) => {
			c.onBuilt(() => hook(c));
			if (order) c.onStop(() => void order.push(`stop ${name}`));
		}),
	]);

const refusing = defineModule({ name: "refusing", replicaSafe: true, takes: [] }, (m) => [
	m.provide(contract<void>("refused")).by((c) => c.refuse("refusing", "refused on purpose")),
]);

const assembled = (modules: readonly Module[]) =>
	assemble({ modules, config: single, runtime: quietRuntime() });

describe("a hook on an assembly no build refused", () => {
	it("runs once, before assemble answers and before start, in the order registered", async () => {
		const order: string[] = [];
		const noting = (name: string) => () => void order.push(name);
		const app = await assembled([
			hooking("first", noting("first")),
			hooking("next", noting("next")),
		]);
		expect(order).toEqual(["first", "next"]);
		await app.start();
		await app.stop(1000);
		expect(order).toEqual(["first", "next"]);
	});

	it("waits for each, one at a time", async () => {
		const order: string[] = [];
		await assembled([
			hooking("slow", async () => {
				await new Promise((resolve) => setTimeout(resolve, 5));
				order.push("slow");
			}),
			hooking("quick", () => void order.push("quick")),
		]);
		expect(order).toEqual(["slow", "quick"]);
	});

	it("does not run after a refusal", async () => {
		const order: string[] = [];
		const refused = await refusalsOf(
			assembled([hooking("held", () => void order.push("held")), refusing]),
		);
		expect(refused).toEqual([{ where: "refusing", reason: "refused on purpose" }]);
		expect(order).toEqual([]);
	});

	it("takes the same refusal as a build, runs the stop hooks in reverse, and starts no later hook", async () => {
		const order: string[] = [];
		const refused = await refusalsOf(
			assembled([
				hooking("base", () => void order.push("base"), order),
				hooking("judging", (c) => c.refuse("judging", "not as it was judged"), order),
				hooking("later", () => void order.push("later"), order),
			]),
		);
		expect(refused).toEqual([{ where: "judging", reason: "not as it was judged" }]);
		expect(order).toEqual(["base", "stop later", "stop judging", "stop base"]);
	});

	it("refuses with every refusal a hook gives at once", async () => {
		const refused = await refusalsOf(
			assembled([
				hooking("judging", (c) =>
					c.refuseAll([
						{ where: "judging.a", reason: "one" },
						{ where: "judging.b", reason: "two" },
					]),
				),
			]),
		);
		expect(refused).toHaveLength(2);
	});

	it.each([
		["Unavailable", new Unavailable("store holding s3cret")],
		["an error", new Error("s3cret")],
		["no error at all", "s3cret"],
	])("reads %s thrown as a build's failure, its text never kept, and stops", async (_, thrown) => {
		const order: string[] = [];
		const attempt = assembled([
			hooking(
				"throwing",
				() => {
					throw thrown;
				},
				order,
			),
			hooking("later", () => void order.push("later")),
		]);
		await expect(attempt).rejects.toSatisfy((error) => BootRefused.is(error));
		const refused = await refusalsOf(attempt);
		expect(refused).toEqual([{ where: "throwing", reason: "failed during assembly" }]);
		expect(JSON.stringify(refused)).not.toContain("s3cret");
		expect(order).toEqual(["stop throwing"]);
	});

	it("holds a hook to the takes as a build is, a take beyond them refusing though it catches the throw", async () => {
		const other = contract<void>("other");
		const provider = defineModule({ name: "provider", replicaSafe: true, takes: [] }, (m) => [
			m.provide(other).by(() => undefined),
		]);
		const order: string[] = [];
		const refused = await refusalsOf(
			assembled([
				hooking("catching", (c) =>
					c.get(other).then(
						() => undefined,
						() => undefined,
					),
				),
				hooking("later", () => void order.push("later")),
				provider,
			]),
		);
		expect(refused).toEqual([
			{ where: "catching", reason: "takes other, which its takes do not name" },
		]);
		expect(order).toEqual([]);
	});

	it("reads no late reference and no readiness yet, as assembly has not succeeded", async () => {
		const held = contract<void>("held");
		const seen: string[] = [];
		const late = defineModule({ name: "late", replicaSafe: true, takes: [held] }, (m) => [
			m.provide(contract<void>("late")).by((c) => {
				const known = c.late(held);
				c.onBuilt(async () => {
					expect(() => known()).toThrow("used before assembly is done");
					await expect(c.readinessReport(1000)).rejects.toThrow();
					seen.push("checked");
				});
			}),
		]);
		const provider = defineModule({ name: "held", replicaSafe: true, takes: [] }, (m) => [
			m.provide(held).by(() => undefined),
		]);
		await assembled([late, provider]);
		expect(seen).toEqual(["checked"]);
	});
});
