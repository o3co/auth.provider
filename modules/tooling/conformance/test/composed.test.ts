import { describe, expect, it } from "vitest";
import { area, type NewPart, onNew, sceneOf } from "../src/areas.ts";
import { composition } from "../src/drivers/composed.ts";

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
});
