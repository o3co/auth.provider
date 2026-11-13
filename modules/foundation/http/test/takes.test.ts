import { kernelConfig } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import http from "../src/module.ts";
import { httpConfig } from "../src/testing.ts";
import { contributing, double } from "./boot.ts";

it("takes every handle its takes name: the points it collects itself", async () => {
	const modules = [http, contributing("server", double().server)];
	expect(
		(await takesUnused({ modules, config: { ...kernelConfig(), ...httpConfig() } })).http,
	).toBeUndefined();
});
