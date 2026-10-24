import { kernelConfig } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import http from "../src/module.ts";
import { httpConfig } from "../src/testing.ts";

it("takes every handle its takes name: the points it collects itself", async () => {
	expect(
		await takesUnused({ modules: [http], config: { ...kernelConfig(), ...httpConfig() } }),
	).toEqual({});
});
