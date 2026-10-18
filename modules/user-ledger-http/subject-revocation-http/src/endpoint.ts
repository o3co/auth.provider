import { type Audit, declaredAudit } from "@mod/audit";
import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import { isUnavailable, type Log, sameSecret } from "@mod/kernel";
import { type RateLimit, sourceKey, type Window } from "@mod/rate-limit";
import { type AddressList, determinedSource } from "@mod/request-source";
import type { Revocations } from "@mod/subject-revocation";
import { isWellFormedSubject } from "@mod/users";
import events from "./audit-events.ts";

export interface EndpointParts {
	/** The current credential, then the previous one while it is kept. */
	readonly credentials: readonly string[];
	readonly sources: AddressList;
	readonly failures: { readonly limit: RateLimit; readonly window: Window };
	readonly requests: { readonly limit: RateLimit; readonly window: Window };
	readonly revocations: Pick<Revocations, "record">;
	readonly recorded: Pick<Audit, "record">;
	readonly log: Log;
}

type Reason =
	| "https_required"
	| "forbidden_source"
	| "unauthenticated"
	| "rate_limited"
	| "rate_limit_unavailable"
	| "invalid_request";

/** The ledger retries until it gets 200; a few seconds apart is soon enough. */
const retryAfter = { "retry-after": "5" };
const bearer = /^Bearer +([^\s]+)$/i;
/** Of an ASCII subject, 0x00 to 0x1f and 0x7f. */
const control = /\p{Cc}/u;

/** A subject users takes, without ASCII control characters, as it goes into store keys and the audit. */
const isSubject = (value: unknown): value is string =>
	isWellFormedSubject(value) && !control.test(value);

/** The handler of `POST /ledger/subject-revocations`, checking in order: scheme, credential and source, the windows, the body. */
export function endpointOf(parts: EndpointParts) {
	const audit = declaredAudit(parts.recorded, events);
	const known = (presented: string | undefined) =>
		// Each credential is compared, so which one matched takes no less time.
		parts.credentials
			.map((credential) => presented !== undefined && sameSecret(presented, credential))
			.includes(true);

	return async (request: HttpRequest): Promise<HttpResponse> => {
		const source = determinedSource(request);
		const told = source ?? request.source.address;
		const denied = (reason: Reason, answer: HttpResponse) => {
			audit.record("subject.revocation.denied", { attributes: { reason, source: told } });
			return answer;
		};
		/** Counts one use in a window: undefined when it is allowed, else the answer. */
		const counted = async (window: EndpointParts["failures"], name: string) => {
			const hit = await window.limit.hit(name, sourceKey(told), window.window).catch((error) => {
				if (isUnavailable(error)) return undefined;
				throw error;
			});
			if (hit === undefined) {
				return denied(
					"rate_limit_unavailable",
					jsonAnswer(503, { error: "temporarily_unavailable" }, { headers: retryAfter }),
				);
			}
			if (hit.kind === "allowed") return undefined;
			const seconds = String(Math.ceil(hit.retryAfterMs / 1000));
			return denied(
				"rate_limited",
				jsonAnswer(429, { error: "rate_limited" }, { headers: { "retry-after": seconds } }),
			);
		};

		if (request.source.scheme !== "https") {
			return denied("https_required", jsonAnswer(403, { error: "https_required" }));
		}
		const authenticated = known(bearer.exec(request.headers.get("authorization") ?? "")?.[1]);
		const inside = source !== undefined && parts.sources.has(source);
		if (!inside || !authenticated) {
			const limited = await counted(parts.failures, "subject-revocation-http.failures");
			if (limited) return limited;
			// One outside learns nothing of its credential.
			return inside
				? denied(
						"unauthenticated",
						jsonAnswer(
							401,
							{ error: "unauthenticated" },
							{ headers: { "www-authenticate": "Bearer" } },
						),
					)
				: denied("forbidden_source", jsonAnswer(403, { error: "forbidden_source" }));
		}
		const limited = await counted(parts.requests, "subject-revocation-http.requests");
		if (limited) return limited;

		const { subject, delegations = "end" } = request.json ?? {};
		if (!isSubject(subject) || (delegations !== "end" && delegations !== "keep")) {
			return denied("invalid_request", jsonAnswer(400, { error: "invalid_request" }));
		}
		const outcome = await parts.revocations
			.record(subject, { keepDelegations: delegations === "keep" })
			.then(({ complete }) => (complete ? "complete" : "incomplete"))
			.catch((error) => {
				if (isUnavailable(error)) return "unknown" as const;
				throw error;
			});
		audit.record("subject.revocation.requested", {
			subject,
			attributes: { delegations, outcome, source: told },
		});
		if (outcome === "complete") return jsonAnswer(200, { complete: true });
		parts.log.warn(`subject-revocation-http.${outcome}`, {});
		return jsonAnswer(
			503,
			{ error: "temporarily_unavailable", state: outcome },
			{ headers: retryAfter },
		);
	};
}
