import cookiesModule from "@mod/cookies/module";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import { expect, it } from "vitest";
import { roundTripStore, roundTrips, type StoredRoundTrip } from "../src/contract.ts";
import roundTripModule from "../src/module.ts";

it("provides round trips over the composed store and cookies", async () => {
	const kept = memoryRecords<StoredRoundTrip>(() => 0, { shards: 1, perShard: 1 });
	const store = defineModule({ name: "round-trip-store" }, (m) => [
		m
			.provide(roundTripStore)
			.by(() => ({ save: kept.records.create, update: kept.records.change })),
	]);
	const app = await assemble({
		modules: [http, cookiesModule, store, roundTripModule],
		config: { ...kernelConfig(), ...httpConfig({ "public-origin": "https://as.example" }) },
		runtime: quietRuntime({ clock: { now: () => 0 } }),
	});
	const trips = app.get(roundTrips);
	const begun = await trips.begin({ name: "a", carried: "kept", lifetimeMs: 60_000 });
	const request = testRequest({
		headers: new Map([["cookie", begun.cookie.split(";")[0] ?? ""]]),
		source: { scheme: "https" },
	});
	expect(await trips.take(request, "a", begun.state)).toMatchObject({
		kind: "taken",
		carried: "kept",
	});
});
