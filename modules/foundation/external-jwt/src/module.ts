import { defineModule, setting } from "@mod/kernel";
import { outbound } from "@mod/outbound";
import { z } from "zod";
import { externalJwt } from "./contract.ts";
import { externalJwtOver } from "./verifier.ts";

export const section = z
	.strictObject({
		"key-set-max-age": setting
			.duration("ms")
			.pipe(z.number().int().min(3_600_000).max(2_592_000_000))
			.prefault("1d")
			.describe(
				"How long after its fetch a key set is still used while no new one can be had, from `1h` to `30d`.",
			),
		"key-set-refresh": setting
			.duration("ms")
			.pipe(z.number().int().min(60_000).max(2_592_000_000))
			.prefault("1h")
			.describe(
				"How long after its fetch a key set is used before it is fetched again, from `1m` to `30d` and no longer than `key-set-max-age`; fetches stay at least a minute apart.",
			),
	})
	.refine((s) => s["key-set-refresh"] <= s["key-set-max-age"], {
		message: "key-set-refresh is longer than key-set-max-age",
		path: ["key-set-refresh"],
	});

export default defineModule(
	// Safe on many instances: each keeps its own key sets, `key-set-refresh` (stale ones up to `key-set-max-age`), so
	// hosts may hold different versions, as one host does across a fetch.
	{ name: "external-jwt", replicaSafe: true, section, takes: [outbound] },
	(m) => [
		m.provide(externalJwt).by(async (c) =>
			externalJwtOver({
				clock: c.clock,
				outbound: await c.get(outbound),
				keySetMaxAgeMs: c.section["key-set-max-age"],
				keySetRefreshMs: c.section["key-set-refresh"],
			}),
		),
	],
);
