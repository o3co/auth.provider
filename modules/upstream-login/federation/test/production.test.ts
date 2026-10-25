import { expect, it } from "vitest";
import federationModule from "../src/module.ts";

it("refuses in production a held page on a loopback host", () => {
	const ask = (page: string | undefined) =>
		federationModule.refusedInProduction?.({ "held-page": page } as never)?.map((r) => r.key);
	expect(ask("http://localhost:3000/held")).toEqual(["held-page"]);
	expect(ask("https://as.example/held")).toEqual([]);
	expect(ask(undefined)).toEqual([]);
});
