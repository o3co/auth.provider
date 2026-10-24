import { kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import webauthnModule from "../src/module.ts";
import { webauthnConfig } from "../src/testing.ts";

it("takes all it names", async () => {
	const input = {
		modules: [webauthnModule],
		config: { ...kernelConfig(), ...webauthnConfig() },
		runtime: quietRuntime(),
	};
	expect(await takesUnused(input)).toEqual({});
});
