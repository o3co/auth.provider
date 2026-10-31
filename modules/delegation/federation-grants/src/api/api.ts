import { type Audit, audit } from "@mod/audit";
import { type Clients, clients, recordRefusedAuthentication } from "@mod/clients";
import type { HttpRequest, HttpResponse } from "@mod/http";
import { type BuildContext, type Clock, isUnavailable, type Random } from "@mod/kernel";
import { attemptLimit, type RateLimit } from "@mod/rate-limit";
import { type Upstreams, upstreams } from "@mod/upstreams";
import type { Judge, Listing, Records } from "../grant/grant.ts";
import { shared } from "../grant/shared.ts";
import { type Refresh, refreshOver, refreshTakes } from "../refresh/refresh.ts";
import type { Settings } from "../section.ts";
import {
	type GrantStore,
	grantStore,
	type PendingIntents,
	pendingIntents,
	type StepStore,
	stepStore,
} from "../store.ts";
import { apiCommonWith, error } from "./common.ts";
import { lodgingWith } from "./lodging/lodging.ts";
import { revokingWith } from "./revoking/revoking.ts";
import { routingWith } from "./routing/routing.ts";
import { tokeningWith } from "./tokening/tokening.ts";

export interface ApiParts {
	readonly clients: Clients;
	readonly grants: GrantStore;
	readonly steps: StepStore;
	readonly pending: PendingIntents;
	readonly lodges: RateLimit;
	readonly records: Records;
	readonly judge: Judge;
	readonly listed: Listing;
	readonly refresh: Refresh;
	readonly upstreams: Upstreams;
	readonly audit: Audit;
	readonly settings: Settings;
	readonly origin: string;
	readonly clock: Clock;
	readonly random: Random;
}

export const base = "/oauth/federation-grants";

/** The client routes: lodging an intent, renewing a grant, and a grant's token, status and revocation. */
export function apiWith(p: ApiParts) {
	const common = apiCommonWith(p);
	const { lodge, reauthorize } = lodgingWith(common);
	const { token, status } = tokeningWith(common);
	const { revoke } = revokingWith(common);
	const { byId } = routingWith(common, { reauthorize, token, status, revoke });
	return async (request: HttpRequest): Promise<HttpResponse> => {
		try {
			const authenticated = await p.clients.authenticate(request);
			if (authenticated.kind === "refused")
				recordRefusedAuthentication(p.audit, request, authenticated);
			if (authenticated.kind === "refused" || authenticated.client.kind !== "confidential") {
				const challenges = authenticated.kind === "refused" ? authenticated.challenges : [];
				return error(
					401,
					"invalid_client",
					undefined,
					challenges.length > 0 ? { "www-authenticate": challenges.join(", ") } : {},
				);
			}
			const client = authenticated.client;
			if (request.path === base) return await lodge(request, client);
			const [id = "", step = "", ...rest] = request.path.slice(base.length + 1).split("/");
			if (id === "" || rest.length > 0) return error(404, "not_found");
			return await byId(request, client, id, step);
		} catch (thrown) {
			if (isUnavailable(thrown)) return error(503, "temporarily_unavailable");
			throw thrown;
		}
	};
}

export const apiTakes = [
	...refreshTakes,
	clients,
	grantStore,
	stepStore,
	pendingIntents,
	attemptLimit,
	upstreams,
	audit,
] as const;

/** The client routes' handler, over the contracts the assembly gives. */
export async function apiOver(c: BuildContext<Settings>) {
	const parts = await c.get(shared);
	return apiWith({
		...parts,
		clients: await c.get(clients),
		grants: await c.get(grantStore),
		steps: await c.get(stepStore),
		pending: await c.get(pendingIntents),
		lodges: await c.get(attemptLimit),
		refresh: await refreshOver(c, parts.records, parts.judge),
		upstreams: await c.get(upstreams),
		audit: await c.get(audit),
		settings: c.section,
		clock: c.clock,
		random: c.random,
	});
}
