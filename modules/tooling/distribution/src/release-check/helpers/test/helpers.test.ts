import { assemble, kernelConfig } from "@mod/kernel";
import { expect, it } from "vitest";
import { lookupConfig, lookupModules } from "../helpers.ts";

it("boots the outbound the helpers scene runs once more in the image, from the modules it names", async () => {
	const modules = await Promise.all(
		lookupModules.map(async (name) => (await import(`@mod/${name}/module`)).default),
	);
	const app = await assemble({
		modules,
		config: { ...kernelConfig(), ...lookupConfig("localhost:3000") },
	});
	await expect(app.stop()).resolves.toBeUndefined();
});
