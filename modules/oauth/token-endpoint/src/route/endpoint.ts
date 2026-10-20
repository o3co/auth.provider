import { type Audit, declaredAudit } from "@mod/audit";
import { clientAllowance } from "@mod/client-allowance";
import type { Client, Clients } from "@mod/clients";
import type { Grant, GrantInput, SessionIssuance, TargetRule } from "@mod/grants";
import { type HttpRequest, type HttpResponse, jsonAnswer, type Route } from "@mod/http";
import { determinedSource } from "@mod/request-source";
import type { Binding, ClientBindings, SenderBindings } from "@mod/sender-binding";
import type { Tokens } from "@mod/tokens";
import events from "../audit-events.ts";
import { authenticateClient, oauthError } from "../contract.ts";
import { answeredBody } from "./answer.ts";
import { challenged } from "./challenges.ts";
import { issuanceFor, refusedAnswer } from "./issuance.ts";

export const tokenPath = "/oauth/token";

/** How a grant reads the request's parameters: single strings by name, and members as sent. */
export const readerOf = ({ fields, json }: HttpRequest) => ({
	param: (name: string) => fields.single(name),
	value: (name: string): unknown =>
		json ? (Object.hasOwn(json, name) ? json[name] : undefined) : fields.single(name),
});

/** The OAuth token request parameters, each one string; `assertion` is its grant's to define. */
const oauthParameters = new Set([
	...["grant_type", "scope", "client_id", "client_secret", "code", "redirect_uri"],
	...["refresh_token", "username", "password", "code_verifier", "device_code"],
	...["client_assertion", "client_assertion_type", "audience", "resource"],
	...["subject_token", "subject_token_type", "actor_token", "actor_token_type"],
	"requested_token_type",
]);

/** The first OAuth parameter sent in JSON as neither a string nor null (which is as if left out). */
const mistypedOf = ({ json, mistyped }: HttpRequest) =>
	[...(mistyped ?? [])].find((name) => oauthParameters.has(name) && json?.[name] !== null);

/** The refusal of a request whose OAuth parameter is mistyped, before any grant runs; none for another. */
export const mistypedRefusal = (request: HttpRequest) => {
	const mistyped = mistypedOf(request);
	return mistyped === undefined
		? undefined
		: { error: "invalid_request", description: `${mistyped} must be a string` };
};

/** What a grant is handed once the request has passed the endpoint: its reader, the audience rule and issuance. */
export function grantInputOf(parts: {
	readonly request: HttpRequest;
	readonly client: Client;
	readonly grantType: string;
	readonly binding: Binding | undefined;
	readonly targets: TargetRule;
	readonly tokens: Tokens;
	readonly told: readonly SessionIssuance[];
}): GrantInput {
	const { request, client, grantType, binding, targets, tokens, told } = parts;
	const { param, value } = readerOf(request);
	return {
		request,
		client,
		param,
		value,
		target: (audience, within) => targets.target({ param, audience, within }),
		...(binding ? { binding } : {}),
		...issuanceFor(tokens, grantType, binding, told),
	};
}

/** The endpoint's handler and its answer to Unavailable. */
export function tokenEndpoint(
	clients: Clients,
	tokens: Tokens,
	told: readonly SessionIssuance[],
	bindings: SenderBindings,
	required: ClientBindings,
	grants: ReadonlyMap<string, Grant>,
	targets: TargetRule,
	audit: Audit,
): Pick<Route, "handle" | "unavailable"> {
	const recorded = declaredAudit(audit, events);
	const answer = async (request: HttpRequest): Promise<HttpResponse> => {
		const authenticated = await authenticateClient(clients, request);
		if (authenticated.kind === "refused") return authenticated.response;
		const client = authenticated.client;
		const source = determinedSource(request);
		// Once the client is known, each answer but an unavailable one is recorded; a known grant type is named.
		const record = (
			grantType: string | undefined,
			failure?: { reason: string; error: string; policy?: string; refusal?: string },
		) => {
			const attributes = {
				client: client.id,
				...(source === undefined ? {} : { source }),
				...(grantType === undefined ? {} : { grant_type: grantType }),
			};
			if (failure)
				recorded.record("token.issued.failure", { attributes: { ...attributes, ...failure } });
			else recorded.record("token.issued", { attributes });
		};
		const refuse = (failure: {
			readonly grantType?: string;
			readonly reason: string;
			readonly error: string;
			readonly description?: string;
		}) => {
			record(failure.grantType, { reason: failure.reason, error: failure.error });
			return oauthError(400, failure.error, failure.description);
		};
		const repeated = request.fields.repeated();
		if (repeated.length > 0) {
			// A parameter the rule reads, sent twice, is the rule's to answer (RFC 8707 §2's invalid_target).
			const ruled = repeated.map((name) => targets.repeated?.(name)).find((r) => r !== undefined);
			if (ruled) {
				const { error, description } = ruled;
				return refuse({ reason: "repeated_parameter", error, description });
			}
			const description = "repeated parameter";
			return refuse({ reason: "repeated_parameter", error: "invalid_request", description });
		}
		const mistyped = mistypedRefusal(request);
		if (mistyped) return refuse({ reason: "mistyped_parameter", ...mistyped });
		const { param } = readerOf(request);
		const grantType = param("grant_type");
		if (!grantType) {
			const description = "grant_type is required";
			return refuse({ reason: "missing_grant_type", error: "invalid_request", description });
		}
		const grant = grants.get(grantType);
		// An unsupported grant type is the client's own input, so it is not named.
		if (!grant)
			return refuse({ reason: "unsupported_grant_type", error: "unsupported_grant_type" });
		// A request with no body is read as a form, the body RFC 6749 §3.2 defines.
		const body = request.json ? "json" : "form";
		if (!(grant.bodies ?? ["form"]).includes(body)) {
			return refuse({
				grantType,
				reason: "unsupported_body",
				error: "invalid_request",
				description: `no ${body} body for this grant`,
			});
		}
		if (!clientAllowance.allowsGrant(client, grantType)) {
			return refuse({ grantType, reason: "grant_type_not_allowed", error: "unauthorized_client" });
		}
		const bound = await bindings.bindingOf(request, { kind: "issue" });
		if (bound.kind === "multiple_bindings") {
			return refuse({
				grantType,
				reason: "multiple_bindings",
				error: "invalid_request",
				description: "use one sender binding",
			});
		}
		if (bound.kind === "refused") {
			// Like any unavailable answer, an unavailable binding is not recorded.
			if (!bound.unavailable) record(grantType, { reason: "binding_refused", error: bound.error });
			const response = oauthError(bound.unavailable ? 503 : 400, bound.error, bound.description);
			return { ...response, headers: { ...response.headers, ...bound.headers } };
		}
		const binding = bound.kind === "bound" ? bound.binding : undefined;
		const unmet = required.refusalOf(client, binding);
		if (unmet === "required") {
			const description = "this client must bind its token";
			return refuse({
				grantType,
				reason: "binding_required",
				error: "invalid_request",
				description,
			});
		}
		if (unmet === "kind") {
			const description = "a binding of a kind this client does not name";
			const failure = {
				reason: "binding_kind_not_named",
				error: "unauthorized_client",
				description,
			};
			return refuse({ grantType, ...failure });
		}
		// Asked before the grant runs, so a grant that would ignore the audience asked uses nothing up.
		const untargeted = grant.targets ? undefined : targets.untargeted?.({ param });
		if (untargeted) {
			const { error, description } = untargeted;
			return refuse({ grantType, reason: "untargeted", error, description });
		}
		const input = grantInputOf({ request, client, grantType, binding, targets, tokens, told });
		const outcome = await grant.handle(input);
		// One answer for every grant; the audit names the policy and its reason, never a value.
		if (outcome.kind === "refused") {
			const { error, description } = refusedAnswer(outcome);
			const { policy, reason } = outcome.refusal;
			record(grantType, { reason: "issuance_refused", error, policy, refusal: reason });
			return oauthError(400, error, description);
		}
		if (outcome.kind === "error") {
			record(grantType, { reason: "grant_refused", error: outcome.error });
			// A status but 400 or 401 is answered as if the grant named none.
			const named = outcome.status === 400 || outcome.status === 401 ? outcome.status : undefined;
			const status = named ?? (outcome.error === "invalid_client" ? 401 : 400);
			const response = oauthError(status, outcome.error, outcome.description, outcome.members);
			return status === 401 ? challenged(response, authenticated.challenges) : response;
		}
		record(grantType);
		return jsonAnswer(200, answeredBody(outcome.body));
	};
	return {
		handle: answer,
		unavailable: {
			response: oauthError(503, "temporarily_unavailable"),
			// Only a grant type it dispatches to is named, so a client's input never reaches the log.
			noted: (request) => {
				const grantType = request.fields.single("grant_type");
				return grantType !== undefined && grants.has(grantType)
					? { grant_type: grantType }
					: undefined;
			},
		},
	};
}
