import { BootRefused, defineModule } from "@mod/kernel";
import { expect, it } from "vitest";
import { harness } from "../../../test/harness.ts";
import { grantsBrowsers } from "../../browser.ts";
import { browserAmong } from "../connect.ts";

it("answers through the one browser half contributed, its own where none is, and none where two are", () => {
	expect(browserAmong([])).toBe("none");
	const contributed = { name: "contributed" };
	expect(browserAmong([contributed])).toBe(contributed);
	expect(browserAmong([contributed, { name: "another" }])).toBe("many");
});

it("serves the browser routes through a contributed browser half, and refuses two at boot", async () => {
	const answer = { status: 299, headers: {} };
	const contributing = (name: string) =>
		defineModule({ name }, (m) => [
			m.contribute(grantsBrowsers).by(() => ({
				connect: async () => answer,
				question: async () => answer,
				decide: async () => answer,
				callback: async () => answer,
			})),
		]);
	const h = await harness({ modules: [contributing("browser-half")] });
	expect((await h.browse("GET", "/session/federation-grants/connect", "", {})).status).toBe(299);
	const refused = await harness({
		modules: [contributing("browser-half"), contributing("another-half")],
	}).catch((error: unknown) => error);
	expect(refused).toBeInstanceOf(BootRefused);
});

it("boots a contributed browser half with connections and no page of the package's own", async () => {
	const answer = { status: 299, headers: {} };
	const contributed = defineModule({ name: "browser-half" }, (m) => [
		m.contribute(grantsBrowsers).by(() => ({
			connect: async () => answer,
			question: async () => answer,
			decide: async () => answer,
			callback: async () => answer,
		})),
	]);
	const h = await harness({ settings: { page: undefined }, modules: [contributed] });
	expect((await h.browse("GET", "/session/federation-grants/connect", "", {})).status).toBe(299);
	// With none contributed, the package's own still needs it.
	const refused = await harness({ settings: { page: undefined } }).catch((error: unknown) => error);
	expect(refused).toBeInstanceOf(BootRefused);
});
