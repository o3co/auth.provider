import { defineModule } from "@mod/kernel";
import { ceremoniesFor } from "./ceremony/ceremony.ts";
import { ceremonies } from "./contract.ts";
import { type Settings, section } from "./section.ts";

const relyingParty = (s: Settings) => ({
	id: s["rp-id"],
	name: s["rp-name"],
	origins: s.origins,
	topOrigins: s["top-origins"],
	timeoutMs: s["challenge-lifetime"] * 1000,
});

/** In production, each list holding an http origin, which the origins take on localhost alone. */
const localOriginsRefused = (s: Settings) =>
	(["origins", "top-origins"] as const)
		.filter((key) => (s[key] ?? []).some((entry) => entry.startsWith("http:")))
		.map((key) => ({
			key,
			reason:
				"holds an http origin on localhost, which a production deployment does not take; set kernel.environment = development to try one",
		}));

export default defineModule(
	{
		name: "webauthn",
		section,
		replicaSafe: true,
		refusedInProduction: localOriginsRefused,
		takes: [],
	},
	(m) => [
		m
			.provide(ceremonies)
			.by((c) => ceremoniesFor(relyingParty(c.section), c.random.bytes, c.clock.now)),
	],
);
