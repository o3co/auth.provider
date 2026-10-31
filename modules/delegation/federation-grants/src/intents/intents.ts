import { type Audit, audit } from "@mod/audit";
import { type Clients, clients } from "@mod/clients";
import type { BuildContext, Clock, Log, Random } from "@mod/kernel";
import { type Upstreams, upstreams } from "@mod/upstreams";
import { z } from "zod";
import type { GrantIntents } from "../browser.ts";
import type { Judge, Listing, Records } from "../grant/grant.ts";
import { shared } from "../grant/shared.ts";
import { connectionName, type Settings } from "../section.ts";
import {
	type GrantStore,
	grantStore,
	type PendingIntents,
	pendingIntents,
	type StepStore,
	stepStore,
} from "../store.ts";
import { callbackWith } from "./callback.ts";
import { commonWith } from "./common.ts";
import { foundOf } from "./found.ts";
import { steppingWith } from "./stepping.ts";

export interface IntentsParts {
	readonly clients: Clients;
	readonly upstreams: Upstreams;
	readonly grants: GrantStore;
	readonly steps: StepStore;
	readonly pending: PendingIntents;
	readonly records: Records;
	readonly judge: Judge;
	readonly listed: Listing;
	readonly audit: Audit;
	readonly settings: Settings;
	readonly origin: string;
	readonly clock: Clock;
	readonly random: Random;
	readonly log: Log;
}

/** Where the browser's steps are served, below the public origin. */
export const browserBase = "/session/federation-grants";

/** What a connection's round trip carries for its callback: the grant, its intent and the session that decided. */
export const carried = z.strictObject({
	grant: z.string(),
	intent: z.string(),
	session: z.string(),
});

/** A grant's intents through the browser, over its records. */
export function intentsWith(p: IntentsParts): GrantIntents {
	const common = commonWith(p);
	const { settings } = p;
	const { callbackUrl, failed, failure, audited } = common;
	const stepping = steppingWith(common);
	const callback = callbackWith(common);
	return {
		connected: Object.keys(settings.connections).length > 0,
		connectUrl: (handle) => `${p.origin}${browserBase}/connect?request=${handle}`,
		callbackUrl,
		callbackOf: (path) => {
			const prefix = `${browserBase}/callback/`;
			const named = path.startsWith(prefix) ? path.slice(prefix.length) : undefined;
			return named !== undefined && connectionName.safeParse(named).success ? named : undefined;
		},
		...stepping,
		...callback,
		failed,
		noted: (ref, outcome, from) => failure(foundOf(ref), outcome, from),
		unanswered: (from) =>
			audited.record("federation.grant.authorization_failed", {
				attributes: { outcome: "unavailable", ...(from.source ? { source: from.source } : {}) },
			}),
	};
}

export const intentsTakes = [
	clients,
	upstreams,
	grantStore,
	stepStore,
	pendingIntents,
	audit,
] as const;

/** The intents over the contracts the assembly gives. */
export const intentsOver = async (c: BuildContext<Settings>) =>
	intentsWith({
		...(await c.get(shared)),
		clients: await c.get(clients),
		upstreams: await c.get(upstreams),
		grants: await c.get(grantStore),
		steps: await c.get(stepStore),
		pending: await c.get(pendingIntents),
		audit: await c.get(audit),
		settings: c.section,
		clock: c.clock,
		random: c.random,
		log: c.log,
	});
