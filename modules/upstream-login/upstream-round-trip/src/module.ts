import { cookies } from "@mod/cookies";
import { defineModule } from "@mod/kernel";
import { roundTrips } from "./contract.ts";
import { roundTripsOver } from "./round-trips.ts";
import { roundTripStore } from "./store.ts";

export default defineModule(
	{ name: "upstream-round-trip", takes: [cookies, roundTripStore] },
	(m) => [
		m.provide(roundTrips).by(async (c) =>
			roundTripsOver({
				store: await c.get(roundTripStore),
				cookies: await c.get(cookies),
				random: c.random,
				clock: c.clock,
			}),
		),
	],
);
