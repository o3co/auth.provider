import { describe, expect, it, vi } from "vitest";
import { area, type NewPart, onNew, sceneOf } from "../src/areas.ts";
import { appConfig } from "../src/drivers/app.ts";
import { composition } from "../src/drivers/composed.ts";

// Its first test lists the workspace's packages through pnpm (`pnpm ls -r`, run once per process
// by the composition it reads): pnpm's own start takes 2.5 to 4 seconds on a busy machine, the most
// of the default five, so the tests here are given the time that listing takes.
vi.setConfig({ testTimeout: 30_000 });

const probe = area<NewPart>("composed-probe");
onNew(probe, (part, _, modules) => ({
	...part,
	config: {
		probe: {
			session: modules.includes("@mod/session-lifecycle"),
			store: modules.includes("@mod/store"),
		},
	},
}));
const composed = (part: NewPart) => composition(sceneOf(probe.part(part)));

describe("the new system composed of a scene's parts", () => {
	it("sets each part up knowing the modules composed, for the sections it gives", () => {
		const { modules, config } = composed({ modules: ["@mod/keys"], store: "volatile" });
		expect(modules.slice(0, 6)).toEqual([
			"@mod/http",
			"@mod/keys",
			"@mod/audit",
			"@mod/audit-http",
			"@mod/outbound",
			"@mod/store",
		]);
		expect(config.probe).toEqual({ session: false, store: true });
		// The generated configuration holds no value, so the scene states the deployment.
		expect(config.kernel).toEqual({ deployment: "single" });
	});

	it("takes the deployment a part gives over the single one, keeping the part's other kernel keys", () => {
		const own = area<NewPart>("composed-kernel");
		onNew(own, (part) => part);
		const kernel = { deployment: "multi", logging: { level: "debug" } };
		const { config } = composition(
			sceneOf(own.part({ modules: ["@mod/keys"], config: { kernel } })),
		);
		expect(config.kernel).toEqual(kernel);
	});

	it("composes the modules a listed module needs, with their wirings, and tells the parts", () => {
		const { modules, config } = composed({ modules: ["@mod/logout"] });
		// Session is composed as its default, session-lifecycle, with that one's wiring.
		expect(modules).toEqual(
			expect.arrayContaining(["@mod/session-lifecycle", "@mod/session-store"]),
		);
		expect(modules).not.toContain("@mod/oidc");
		expect(config.probe).toEqual(expect.objectContaining({ session: true }));
	});

	it("keeps the store each mark composes in place of the one a module needs", () => {
		const pausable = composed({ modules: ["@mod/rate-limit"], store: "pausable" }).modules;
		expect(pausable).toContain("@mod/redis");
		expect(pausable).not.toContain("@mod/store");
		const volatile = composed({ modules: ["@mod/rate-limit"], store: "volatile" }).modules;
		expect(volatile).toContain("@mod/store");
		expect(volatile).not.toContain("@mod/redis");
	});

	it("refuses a scene about the absence of a module another one needs", () => {
		expect(() =>
			composed({ modules: ["@mod/logout"], without: ["@mod/session-lifecycle"] }),
		).toThrow("absence of @mod/session-lifecycle");
		expect(composed({ modules: ["@mod/keys"], without: ["@mod/oidc"] }).modules).not.toContain(
			"@mod/oidc",
		);
	});

	it("refuses a scene about the absence of an owner whose default adapter composes in its place", () => {
		// session-lifecycle replaces session, so a scene without session cannot hold where logout needs one.
		expect(() => composed({ modules: ["@mod/logout"], without: ["@mod/session"] })).toThrow(
			"absence of @mod/session",
		);
	});

	it("keeps each part's configuration file as written, and boots it below the scene's sections and over the rest", () => {
		const layer = "users { registered = [] }\n";
		expect(composed({ modules: ["@mod/keys"], layer }).layers).toEqual([layer]);
		expect(composed({ modules: ["@mod/keys"] }).layers).toEqual([]);
		expect(appConfig("scene.conf", ["part.conf"], "local.conf")).toBe(
			"scene.conf,part.conf,local.conf,config/application.conf",
		);
		expect(appConfig("scene.conf", [])).toBe("scene.conf,config/application.conf");
	});
});
