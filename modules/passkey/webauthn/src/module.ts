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

export default defineModule({ name: "webauthn", section, replicaSafe: true }, (m) => [
	m
		.provide(ceremonies)
		.by((c) => ceremoniesFor(relyingParty(c.section), c.random.bytes, c.clock.now)),
]);
