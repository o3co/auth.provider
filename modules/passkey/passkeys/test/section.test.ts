import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import webauthn from "@mod/webauthn/module";
import { webauthnConfig } from "@mod/webauthn/testing";
import { expect, it } from "vitest";
import passkeysModule from "../src/module.ts";
import { type PasskeysSettings, passkeysConfig } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

const boot = (settings: Partial<PasskeysSettings>) =>
	assemble({
		modules: [memoryStores().module, webauthn, passkeysModule],
		config: { ...kernelConfig(), ...webauthnConfig(), ...passkeysConfig(settings) },
		runtime: quietRuntime(),
	});

it("boots on its defaults, and refuses a limit or a verification out of its range, naming the key", async () => {
	await (await boot({})).stop(1000);
	for (const [settings, where] of [
		[{ "max-credentials": 0 }, "passkeys.max-credentials"],
		[{ "max-credentials": 101 }, "passkeys.max-credentials"],
		[{ "user-verification": "always" as never }, "passkeys.user-verification"],
	] as const) {
		const error = await boot(settings).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect(error, JSON.stringify(settings)).toBeInstanceOf(BootRefused);
		expect((error as BootRefused).refusals.map((r) => r.where)).toEqual([where]);
	}
});
