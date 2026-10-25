import { urlSetting } from "@mod/url-setting";
import { expect, it } from "vitest";
import linkModule from "../src/module.ts";
import { section } from "../src/section.ts";

/** The page setting federation-grants-connect's `step-up-page` is too, so both refuse a page in the same words. */
const page = urlSetting({ schemes: ["https"], loopbackHttp: true });

it("takes a step-up page over https, or http on a loopback host, and none by default", () => {
	expect(section.parse({})).toEqual({});
	for (const url of [
		"https://as.example/raise",
		"http://localhost:3000/raise",
		"http://127.0.0.1/raise",
	]) {
		expect(section.parse({ "step-up-page": url }), url).toEqual({ "step-up-page": url });
	}
});

it("refuses a page as federation-grants-connect's step-up page does, in the same words", () => {
	for (const url of [
		"http://as.example/raise",
		"ftp://as.example/raise",
		"https://as.example/raise#x",
		"raise",
	]) {
		const said = section.safeParse({ "step-up-page": url }).error?.issues.map((i) => i.message);
		const as = page.safeParse(url).error?.issues.map((i) => i.message);
		expect(said, url).toEqual(as);
		expect(said?.length, url).toBeGreaterThan(0);
	}
});

it("refuses in production a step-up page on a loopback host", () => {
	const ask = (url: string) =>
		linkModule.refusedInProduction?.(section.parse({ "step-up-page": url }))?.map((r) => r.key);
	expect(ask("http://localhost:3000/raise")).toEqual(["step-up-page"]);
	expect(ask("https://as.example/raise")).toEqual([]);
});
