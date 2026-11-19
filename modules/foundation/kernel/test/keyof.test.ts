import { describe, expect, it } from "vitest";
import {
	assemble,
	BuildRefused,
	contract,
	defineModule,
	extensionPoint,
	kernelConfig,
} from "../src/contract.ts";
import { refusalsOf } from "./refusals.ts";

const single = kernelConfig();
const refused = { where: "spaces:x", reason: "a space holds records or secret records, not both" };

/** A keyed point whose `keyOf` refuses a contribution, as a library does, or throws plainly. */
const pointThrowing = (thrown: () => unknown) =>
	extensionPoint<{ name: string }>("spaces", {
		multiplicity: "keyed",
		keyOf: () => {
			throw thrown();
		},
	});
const refusing = pointThrowing(() => new BuildRefused(refused.where, refused.reason));

type Point = ReturnType<typeof pointThrowing>;

const contributing = (point: Point, name: string, key = "x") =>
	defineModule({ name, replicaSafe: false, takes: [] }, (m) => [
		m.contribute(point).by(() => ({ name: key })),
	]);

/** A module whose provision collects the point, catching the throw or letting it leave. */
const collecting = (point: Point, name: string, catches: boolean) =>
	defineModule({ name, replicaSafe: false, takes: [point] }, (m) => [
		m.provide(contract<number>(name)).by(async (c) => {
			if (!catches) return (await c.collect(point)).length;
			try {
				return (await c.collect(point)).length;
			} catch {
				return 0;
			}
		}),
	]);

const boot = (...modules: Parameters<typeof assemble>[0]["modules"]) =>
	refusalsOf(assemble({ modules, config: single }));

describe("a point's check, where collect meets it", () => {
	it("refuses the boot under its own where and reason where a factory collects the point, recording nothing more", async () => {
		expect(await boot(collecting(refusing, "store", false), contributing(refusing, "a"))).toEqual([
			refused,
		]);
	});

	it("refuses the boot where the collecting factory catches the throw", async () => {
		expect(await boot(collecting(refusing, "store", true), contributing(refusing, "a"))).toEqual([
			refused,
		]);
	});

	it("refuses the boot where no factory collects the point", async () => {
		expect(await boot(contributing(refusing, "a"))).toEqual([refused]);
	});

	it("refuses the boot once where the first collector catches and the second does not", async () => {
		expect(
			await boot(
				collecting(refusing, "first", true),
				collecting(refusing, "second", false),
				contributing(refusing, "a"),
			),
		).toEqual([refused]);
	});

	it("refuses once for two contributions it refuses, and names no key twice", async () => {
		expect(
			await boot(
				collecting(refusing, "store", false),
				contributing(refusing, "a"),
				contributing(refusing, "b"),
			),
		).toEqual([refused]);
	});

	it("refuses a plain throw as the point's failure on every path, keeping none of its text", async () => {
		const plain = pointThrowing(() => new Error("token=abc"));
		const failed = [{ where: "spaces", reason: "failed during assembly" }];
		expect(await boot(collecting(plain, "store", false), contributing(plain, "a"))).toEqual(failed);
		expect(await boot(collecting(plain, "store", true), contributing(plain, "a"))).toEqual(failed);
		expect(await boot(contributing(plain, "a"))).toEqual(failed);
	});

	it("keeps a point's own refusals once where a collector catches them", async () => {
		const routes = extensionPoint<{ name: string }>("routes", {
			multiplicity: "keyed",
			keyOf: (r) => r.name,
		});
		expect(
			await boot(
				collecting(routes, "first", true),
				collecting(routes, "second", false),
				contributing(routes, "a", "/p"),
				contributing(routes, "b", "/p"),
			),
		).toEqual([{ where: "routes:/p", reason: "more than one contribution for the same key" }]);
	});

	it("checks a point once where assembly checks it before a later contribution's factory collects it", async () => {
		const routes = extensionPoint<{ name: string }>("routes", {
			multiplicity: "keyed",
			keyOf: (r) => r.name,
		});
		const later = extensionPoint<{ name: string }>("later", { multiplicity: "many" });
		const collectingLater = defineModule(
			{ name: "c", replicaSafe: false, takes: [routes] },
			(m) => [
				m.contribute(later).by(async (c) => ({ name: `${(await c.collect(routes)).length}` })),
			],
		);
		expect(
			await boot(contributing(routes, "a", "/p"), contributing(routes, "b", "/p"), collectingLater),
		).toEqual([{ where: "routes:/p", reason: "more than one contribution for the same key" }]);
	});
});
