import { defineModule, setting } from "@mod/kernel";
import { outbound } from "@mod/outbound";
import { z } from "zod";
import { externalJwt } from "./contract.ts";
import { externalJwtOver } from "./verifier.ts";

export const section = z.strictObject({
	"key-set-max-age": setting
		.duration("ms")
		.pipe(z.number().int().min(3_600_000).max(2_592_000_000))
		.prefault("1d")
		.describe(
			"How long after its fetch a key set is still used while no new one can be had, from `1h` to `30d`.",
		),
});

export default defineModule({ name: "external-jwt", section, takes: [outbound] }, (m) => [
	m.provide(externalJwt).by(async (c) =>
		externalJwtOver({
			clock: c.clock,
			outbound: await c.get(outbound),
			keySetMaxAgeMs: c.section["key-set-max-age"],
		}),
	),
]);
