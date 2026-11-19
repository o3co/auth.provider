import { cookies } from "@mod/cookies";
import { erasers } from "@mod/erasure-extensions";
import { defineModule } from "@mod/kernel";
import { roundTrips } from "./contract.ts";
import { roundTripEraser } from "./erasure/eraser.ts";
import { roundTripsOver } from "./round-trips.ts";
import { roundTripStore } from "./store.ts";

export default defineModule(
	{ name: "upstream-round-trip", replicaSafe: true, takes: [cookies, roundTripStore] },
	(m) => [
		m.provide(roundTrips).by(async (c) =>
			roundTripsOver({
				store: await c.get(roundTripStore),
				cookies: await c.get(cookies),
				random: c.random,
				clock: c.clock,
			}),
		),
		// Its build takes only its store, collecting no probes: the erasure gate collects erasers.
		m.contribute(erasers).by(async (c) => roundTripEraser(await c.get(roundTripStore))),
	],
);
