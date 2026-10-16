import { describe, expect, it } from "vitest";
import { area, type NewPart, onNew, patternPartsOf, sceneOf } from "../src/areas.ts";
import { misfit, planOf } from "../src/drivers/pattern.ts";

const memory = ["@mod/http", "@mod/keys", "@mod/store", "@mod/session"];
const redis = ["@mod/http", "@mod/keys", "@mod/redis", "@mod/session"];
const lacking = (reason: string) => ({ kind: "lacking", reason });
const chose = (reason: string) => ({ kind: "alternative", reason });

describe("whether a scene fits a pattern's app", () => {
	it("fits where the app composes every module the parts ask for", () => {
		const parts: NewPart[] = [
			{ modules: ["@mod/keys"] },
			{ modules: ["@mod/session"], store: "volatile" },
		];
		expect(misfit(parts, { parts: {} }, memory)).toBeUndefined();
		expect(misfit(parts, { parts: {} }, redis)).toBeUndefined();
	});

	it("names each module the app does not compose, once", () => {
		const parts = [
			{ modules: ["@mod/dpop", "@mod/keys"] },
			{ modules: ["@mod/mtls", "@mod/dpop"] },
		];
		expect(misfit(parts, { parts: {} }, memory)).toEqual(lacking("lacks @mod/dpop, @mod/mtls"));
	});

	it("leaves out a scene about a module being absent where the app composes it", () => {
		const parts: NewPart[] = [{ modules: ["@mod/keys"], without: ["@mod/dpop", "@mod/session"] }];
		expect(misfit(parts, { parts: {} }, memory)).toEqual({
			kind: "absence",
			reason: "composes @mod/session",
		});
		expect(misfit([{ without: ["@mod/dpop"] }], { parts: {} }, memory)).toBeUndefined();
	});

	it("leaves out pausing the store where it is kept in the process, as the app's alternative", () => {
		expect(misfit([], { parts: {}, storeFaults: true }, memory)).toEqual(chose("pauses the Store"));
		expect(misfit([{ store: "pausable" }], { parts: {} }, memory)).toEqual(
			chose("pauses the Store"),
		);
		expect(misfit([], { parts: {}, storeFaults: true }, redis)).toBeUndefined();
	});

	it("leaves out refusing a store that can lose data where the store keeps it, as the app's alternative", () => {
		const refusing = { parts: {}, acceptVolatileStore: false };
		expect(misfit([{ store: "volatile" }], refusing, redis)).toEqual(
			chose("refuses a volatile Store"),
		);
		expect(misfit([{ store: "volatile" }], refusing, memory)).toBeUndefined();
	});
});

describe("a part an area adapts to a pattern's app", () => {
	it("is left out as an alternative the app chose, unless the app lacks something first", () => {
		const chose = { leaveOut: "chose another" };
		const alternative = { kind: "alternative", reason: "chose another" };
		expect(misfit([chose], { parts: {} }, memory)).toEqual(alternative);
		const both = [chose, { modules: ["@mod/dpop"] }];
		expect(misfit(both, { parts: {} }, memory)).toEqual(lacking("lacks @mod/dpop"));
	});

	it("is set up by the area's adaptation to the app's modules, or as on the new system", () => {
		const adapted = area<string>("adapted-test");
		const plain = area<string>("plain-test");
		const onApp = (part: string, _: unknown, modules: readonly string[]) => ({
			modules: [`${part} on ${modules}`],
		});
		onNew(adapted, () => ({ modules: ["@mod/new"] }), onApp);
		onNew(plain, (part) => ({ modules: [part] }));
		const scene = sceneOf(adapted.part("x"), plain.part("@mod/plain"));
		expect(patternPartsOf(scene, ["@mod/app"])).toEqual([
			{ modules: ["x on @mod/app"] },
			{ modules: ["@mod/plain"] },
		]);
	});
});

describe("how a pattern's app is generated", () => {
	const summaries = [
		{ name: "sso-federated", use: "", areas: [], conformanceAdd: ["@mod/login-password"] },
		{ name: "simple-web", use: "", areas: [] },
	];

	it("adds what the pattern's file asks its conformance run to add, with the audit receiver", () => {
		expect(planOf("sso-federated", summaries)("t")).toMatchObject({
			target: "t",
			template: "sso-federated",
			axes: { "@mod/audit": "@mod/audit-http" },
			add: ["@mod/login-password"],
		});
		expect(planOf("simple-web", summaries)("t")).not.toHaveProperty("add");
	});

	it("generates full as it is, and with every feature that opts in", () => {
		expect(planOf("full", summaries)("t")).toMatchObject({ template: "full" });
		expect(planOf("full", summaries)("t")).not.toHaveProperty("add");
		expect(planOf("full+opt-ins", summaries)("t")).toMatchObject({
			template: "full",
			add: expect.arrayContaining(["@mod/dpop"]),
		});
		// Reading the whole workspace's manifests takes seconds on a loaded host.
	}, 30_000);
});
