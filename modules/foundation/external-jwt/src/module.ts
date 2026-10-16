import { defineModule } from "@mod/kernel";
import { outbound } from "@mod/outbound";
import { z } from "zod";
import { externalJwt } from "./contract.ts";
import { externalJwtOver } from "./verifier.ts";

export const section = z.strictObject({
	"key-set-max-age-ms": z
		.number()
		.int()
		.min(3_600_000)
		.max(2_592_000_000)
		.default(86_400_000)
		.describe(
			"How long after its fetch a key set is still used while no new one can be had, in milliseconds.",
		),
});

export default defineModule({ name: "external-jwt", section }, (m) => [
	m.provide(externalJwt).by(async (c) =>
		externalJwtOver({
			clock: c.clock,
			outbound: await c.get(outbound),
			keySetMaxAgeMs: c.section["key-set-max-age-ms"],
		}),
	),
]);
