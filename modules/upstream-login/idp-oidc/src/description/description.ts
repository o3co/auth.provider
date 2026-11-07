import { withinHosts } from "@mod/host-entries";
import type { Clock, Log } from "@mod/kernel";
import { isUnavailable, Unavailable } from "@mod/kernel";
import {
	DestinationRefused,
	isOutboundUnavailable,
	jsonObjectOf,
	type Outbound,
} from "@mod/outbound";
import {
	browsedRefusalText,
	destinationRefusal,
	type OutboundRefusals,
} from "@mod/outbound-policy";
import { answerOf } from "@mod/upstream-client";
import { UpstreamMismatch, UpstreamRefused } from "@mod/upstreams";
import { z } from "zod";
import { descriptionUrl, narrowerOf, type Settings } from "../settings.ts";
import { describedUserinfoRefusal } from "../userinfo/userinfo.ts";

const description = z.looseObject({
	issuer: z.string(),
	authorization_endpoint: z.url(),
	token_endpoint: z.url(),
	jwks_uri: z.url(),
	end_session_endpoint: z.url().optional(),
	// Read only where the operator reads UserInfo: what a description says of it is no matter otherwise.
	userinfo_endpoint: z.unknown().optional(),
	authorization_response_iss_parameter_supported: z.boolean().optional(),
});

export interface Endpoints {
	readonly authorization: string;
	readonly token: string;
	readonly jwks: string;
	readonly endSession?: string;
	/** Where UserInfo is read, where the operator turns its reading on. */
	readonly userinfo?: string;
}

/** How it reaches the upstream: outbound, and outbound's refusals of a destination at boot. */
export interface Reach {
	readonly outbound: Outbound;
	readonly refusals: OutboundRefusals;
}

/** The endpoints and whether the description offers `iss`, once read. */
export interface Described {
	readonly endpoints: Endpoints;
	readonly offersIss: boolean;
}

/** How long after one read of the description began the next may begin. */
const readsApartMs = 60_000;

/** A description that does not hold, told under `issuer`: the key it was read from. */
const mismatch = (reason: string) => new UpstreamMismatch(reason, ["issuer"]);

/** Why the description cannot be read now, in outbound's word or by the answer's status. */
type Unread = { readonly kind: "unread"; readonly failure: string };

/**
 * The endpoints the issuer's description names, or why it cannot be read now: outbound could not
 * fetch it (its own word), or the upstream answered 5xx or 429. Throws where it does not hold.
 */
async function discovered(
	s: Settings,
	{ outbound, refusals }: Reach,
	hosts: readonly string[],
): Promise<({ readonly kind: "read" } & Described) | Unread> {
	const where = descriptionUrl(s.issuer);
	let fetched: Awaited<ReturnType<Outbound["fetch"]>>;
	try {
		fetched = await outbound.fetch(where, {}, narrowerOf(hosts, s.issuer));
	} catch (error) {
		// A destination outbound refuses is an answer that does not hold, told under the issuer.
		if (DestinationRefused.is(error)) {
			throw mismatch(`outbound's destination policy refuses the description: ${error.reason}`);
		}
		if (!isUnavailable(error)) throw error;
		return {
			kind: "unread",
			failure: isOutboundUnavailable(error) ? error.failure : "unavailable",
		};
	}
	// The upstream cannot answer now: its state, not the settings'.
	if (fetched.status >= 500 || fetched.status === 429) {
		return { kind: "unread", failure: fetched.status === 429 ? "status-429" : "status-5xx" };
	}
	// Any other answer that is no description does not hold.
	const described = answerOf(jsonObjectOf(fetched), description);
	if (described.issuer !== s.issuer) throw mismatch("the description names another issuer");
	const endSession = described.end_session_endpoint;
	// The end of session too: the browser takes the login's id_token there.
	const all = [
		described.authorization_endpoint,
		described.token_endpoint,
		described.jwks_uri,
		...(endSession ? [endSession] : []),
	];
	if (all.some((url) => !withinHosts(url, hosts))) {
		throw mismatch("the description names an endpoint on a host the operator did not name");
	}
	// The browser goes to these, which outbound never reaches: its policy for them decides.
	const browsed = {
		authorization_endpoint: described.authorization_endpoint,
		...(endSession ? { end_session_endpoint: endSession } : {}),
	};
	for (const [name, url] of Object.entries(browsed)) {
		const narrowed = narrowerOf(hosts, s.issuer);
		const refused = browsedRefusalText(refusals, url, narrowed, `the description's ${name}`);
		if (refused !== undefined) throw mismatch(refused);
	}
	// The two this server sends to; a refusal here would fail every login.
	const sent = { token_endpoint: described.token_endpoint, jwks_uri: described.jwks_uri };
	for (const [name, url] of Object.entries(sent)) {
		const narrowed = narrowerOf(hosts, s.issuer);
		const refused = destinationRefusal(refusals, url, narrowed, `the description's ${name}`);
		if (refused !== undefined) throw mismatch(refused);
	}
	// UserInfo only where the operator reads it: a description naming it is no matter otherwise.
	const named = described.userinfo_endpoint;
	const userinfo =
		s["read-userinfo"] && typeof named === "string" && URL.canParse(named) ? named : undefined;
	if (s["read-userinfo"]) {
		const narrowed = narrowerOf(hosts, s.issuer);
		const refused = describedUserinfoRefusal(userinfo, hosts, narrowed, refusals);
		if (refused !== undefined) throw mismatch(refused);
	}
	const endpoints: Endpoints = {
		authorization: described.authorization_endpoint,
		token: described.token_endpoint,
		jwks: described.jwks_uri,
		...(endSession ? { endSession } : {}),
		...(userinfo ? { userinfo } : {}),
	};
	return {
		kind: "read",
		endpoints,
		offersIss: described.authorization_response_iss_parameter_supported === true,
	};
}

/** The endpoints the operator gives without discovery (its settings hold all three then). */
const given = (s: Settings): Endpoints => ({
	authorization: s["authorization-endpoint"] ?? "",
	token: s["token-endpoint"] ?? "",
	jwks: s["jwks-uri"] ?? "",
	...(s["end-session-endpoint"] ? { endSession: s["end-session-endpoint"] } : {}),
	...(s["read-userinfo"] && s["userinfo-endpoint"] ? { userinfo: s["userinfo-endpoint"] } : {}),
});

/**
 * The description, as the upstream takes it: read at boot (or the endpoints given without
 * discovery), or awaited where it could not be read then. Throws, refusing boot, where the
 * description does not hold.
 */
export type Description =
	| { readonly kind: "read"; readonly described: Described }
	| {
			readonly kind: "awaited";
			/** The description once read; else begins a read, where one may, and answers none. */
			now(): Described | undefined;
			/** The description, a read awaited first where one may begin; throws Unavailable without one. */
			when(): Promise<Described>;
	  };

export async function describedBy(
	s: Settings,
	reach: Reach,
	hosts: readonly string[],
	at: { readonly clock: Clock; readonly log: Log; readonly idp: string },
): Promise<Description> {
	if (!s.discovery) return { kind: "read", described: { endpoints: given(s), offersIss: false } };
	const first = await discovered(s, reach, hosts);
	if (first.kind === "read") {
		return { kind: "read", described: { endpoints: first.endpoints, offersIss: first.offersIss } };
	}
	at.log.warn("idp-oidc.description_unavailable", { idp: at.idp, failure: first.failure });
	return awaited(() => discovered(s, reach, hosts), at);
}

/**
 * Reads the description again when it is needed, until a read holds: one read at a time, each
 * beginning at least a minute after the last began. A line is logged only where the outcome changes.
 */
function awaited(
	read: () => ReturnType<typeof discovered>,
	at: { readonly clock: Clock; readonly log: Log; readonly idp: string },
): Description {
	const { clock, log, idp } = at;
	let held: Described | undefined;
	let running: Promise<void> | undefined;
	// The read at boot began this wait.
	let began = clock.now();
	let last: "unread" | "mismatch" = "unread";
	const told = (outcome: "unread" | "mismatch", line: () => void) => {
		if (last !== outcome) line();
		last = outcome;
	};
	const attempt = () => {
		if (held || running) return running;
		if (clock.now() - began < readsApartMs) return undefined;
		began = clock.now();
		running = read()
			.then(
				(outcome) => {
					if (outcome.kind === "read") {
						held = { endpoints: outcome.endpoints, offersIss: outcome.offersIss };
						log.info("idp-oidc.description_read", { idp });
						return;
					}
					const { failure } = outcome;
					told("unread", () => log.warn("idp-oidc.description_unavailable", { idp, failure }));
				},
				(error: unknown) => {
					// Never used: a description that does not hold is told, and the wait goes on.
					const reason = UpstreamMismatch.is(error)
						? error.message
						: UpstreamRefused.is(error)
							? "the upstream does not match its settings"
							: error instanceof Error
								? error.name
								: typeof error;
					told("mismatch", () => log.error("idp-oidc.description_mismatch", { idp, reason }));
				},
			)
			.finally(() => {
				running = undefined;
			});
		return running;
	};
	const unavailable = () => new Unavailable("idp-oidc description");
	return {
		kind: "awaited",
		now: () => {
			if (!held) void attempt();
			return held;
		},
		when: async () => {
			if (!held) await attempt();
			if (held) return held;
			throw unavailable();
		},
	};
}
