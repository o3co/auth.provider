import { createHash } from "node:crypto";
import type { AuthMethod } from "@mod/clients";
import type { Algorithm, ExternalJwt } from "@mod/external-jwt";
import type { HttpRequest } from "@mod/http";
import { type Clock, type Log, Unavailable } from "@mod/kernel";
import { decodeJwt } from "jose";
import { checked } from "./check.ts";
import { clientKeys, keysOf } from "./keys/keys.ts";
import type { SpentAssertions } from "./store.ts";

export const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

export interface Parts {
	readonly spent: SpentAssertions;
	readonly jwt: ExternalJwt;
	/** `issuer`'s URL, the one audience every client's assertion may name. */
	readonly issuer: string;
	/** The token endpoint's absolute URL, which a client accepting a loose audience may name too. */
	readonly tokenEndpoint: string;
	readonly maxLifetimeMs: number;
	readonly skewMs: number;
	/** The algorithms the operator takes. */
	readonly algorithms: readonly Algorithm[];
	readonly clock: Clock;
	readonly log: Log;
}

// Read from the body only, a form or a JSON object; never the query, where an assertion would be logged.
const field = (request: HttpRequest, name: string) => request.fields.single(name);
/** Whether the body sends this name, as a string or of another type. */
const sends = (request: HttpRequest, name: string) =>
	request.fields.has(name) || request.mistyped?.has(name) === true;
const singleFields = ["client_id", "client_assertion", "client_assertion_type"];
const issuerOf = (assertion: string) => {
	try {
		const { iss } = decodeJwt(assertion);
		return typeof iss === "string" ? iss : undefined;
	} catch {
		return undefined;
	}
};

/** A spent assertion's name; JSON keeps the client id and the jti apart, whatever either holds. */
const spentName = (clientId: string, jti: string) =>
	createHash("sha256")
		.update(JSON.stringify([clientId, jti]))
		.digest("base64url");

/** How long a spent name outlives the assertion, for the store's own clock. */
const storeClockMarginMs = 60_000;

/** `private_key_jwt`: the client proves itself with a JWT signed by one of its keys, used once. */
export function assertionMethod(p: Parts): AuthMethod {
	return {
		name: "private_key_jwt",
		signingAlgorithms: p.algorithms,
		// A refusal this method is part of is the assertion's: RFC 7521 §4.2.1 answers it invalid_client.
		assertion: true,
		// Any assertion is this method's to judge (RFC 7521 §4.2.1), so one of a type not taken here
		// is refused rather than left to another method.
		claimed: (request) => {
			// Sent at all, given twice or in JSON not a string, the request uses an assertion.
			if (!sends(request, "client_assertion") && !sends(request, "client_assertion_type")) {
				return undefined;
			}
			// Named by `client_id` when given, which the assertion's issuer must then match. The final
			// "" names no client, so the request stays this method's and is answered as an unknown client.
			return (
				field(request, "client_id") ?? issuerOf(field(request, "client_assertion") ?? "") ?? ""
			);
		},
		// Half an assertion, or a part or the client id given twice or not as a string, is refused
		// before any of it is judged or spent.
		malformed: (request) => {
			if (request.fields.repeated().some((name) => singleFields.includes(name))) return true;
			if (singleFields.some((name) => request.mistyped?.has(name))) return true;
			const typed = request.fields.has("client_assertion_type");
			if (!typed && !request.fields.has("client_assertion")) return false;
			return !(typed && Boolean(field(request, "client_assertion")));
		},
		verify: async (request, client) => {
			const refuse = (reason: string) => {
				p.log.warn("client-assertion.refused", { client: client.id, reason });
				return false;
			};
			if (field(request, "client_assertion_type") !== assertionType) {
				return refuse("assertion type");
			}
			const section = client.section(clientKeys);
			const loose = section["accept-loose-audience"];
			// A verifier over this client's written keys, under the algorithms the operator takes.
			const verifier = p.jwt.verifierOf(keysOf(section), {
				algorithms: p.algorithms,
				skewMs: p.skewMs,
				maxLifetimeMs: p.maxLifetimeMs,
				expect: {
					iss: client.id,
					sub: client.id,
					aud: loose ? [p.issuer, p.tokenEndpoint] : [p.issuer],
				},
			});
			const verified = await verifier.verify(field(request, "client_assertion") ?? "");
			// Written keys are never out of reach; this is for a key source that is fetched.
			if (verified.kind === "unavailable") throw new Unavailable("client keys");
			const assertion = checked(verified, p.issuer);
			if (assertion.kind === "invalid") return refuse(assertion.reason);
			// The issuer alone, as one string, before the jti is spent. An assertion naming the token
			// endpoint, or a list, may have been made for another authorization server that names this
			// one's endpoint, and taken from there (OpenID Foundation, private_key_jwt notice, 2025-01;
			// FAPI 2.0 Security Profile §5.3.2.1). external-jwt takes any one audience of a list.
			if (!assertion.forIssuer) {
				if (!loose) return refuse("audience");
				p.log.warn("client-assertion.loose_audience", { client: client.id });
			}
			// Past the assertion's end by the allowance, and the margin for the store's own clock.
			const lifetimeMs = assertion.expiresAt - p.clock.now() + p.skewMs + storeClockMarginMs;
			const saved = await p.spent.save(spentName(client.id, assertion.jti), lifetimeMs);
			return saved === "exists" ? refuse("used before") : true;
		},
	};
}
