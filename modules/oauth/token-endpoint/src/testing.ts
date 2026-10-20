import { type Client, clients } from "@mod/clients";
import {
	type Grant,
	type GrantInput,
	type GrantOutcome,
	grants,
	type SessionIssuance,
	sessionIssuances,
	type TargetRule,
	targets,
} from "@mod/grants";
import type { HttpRequest } from "@mod/http";
import { contract, deepFreeze, defineModule } from "@mod/kernel";
import type { Binding } from "@mod/sender-binding";
import { type Tokens, tokens } from "@mod/tokens";
import { composedRule, unread } from "./built-in/targets.ts";
import { answeredBody } from "./route/answer.ts";
import { grantInputOf, mistypedRefusal, tokenPath } from "./route/endpoint.ts";
import { refusedAnswer } from "./route/issuance.ts";

/** Calls a contributed grant directly, as the token endpoint does once the request has passed it. */
export interface GrantCalls {
	/**
	 * Sends the parameters as the first body the grant takes: strings in a form, any value in JSON.
	 * A refused issuance comes back as the endpoint's error.
	 */
	call(
		grantType: string,
		clientId: string,
		params: Readonly<Record<string, unknown>>,
		options?: { readonly binding?: Binding; readonly request?: HttpRequest },
	): Promise<GrantOutcome>;
}

export const grantCalls = contract<GrantCalls>("token-endpoint.grant-calls");

/** The string values, one each, as a request carries them. */
const valuesOf = (given: Readonly<Record<string, unknown>>) => {
	const strings = new Map(
		Object.entries(given).filter(
			(entry): entry is [string, string] => typeof entry[1] === "string",
		),
	);
	return Object.assign(new Map([...strings].map(([name, value]) => [name, [value]])), {
		single: (name: string) => strings.get(name),
		repeated: () => [],
	});
};

/** A POST to the token endpoint carrying these parameters as a body of this kind. */
const sentRequest = (params: Readonly<Record<string, unknown>>, kind: string): HttpRequest => {
	const json = kind === "json";
	const other = Object.keys(params).find((name) => typeof params[name] !== "string");
	if (!json && other !== undefined) throw new Error(`a form holds strings only, not ${other}`);
	const fields = valuesOf(params);
	const others = Object.keys(params).filter((name) => typeof params[name] !== "string");
	return {
		method: "POST",
		path: tokenPath,
		query: valuesOf({}),
		form: json ? valuesOf({}) : fields,
		fields,
		...(json ? { json: deepFreeze(structuredClone(params)) } : {}),
		...(json && others.length > 0 ? { mistyped: new Set(others) } : {}),
		headers: new Map(),
		source: { address: "127.0.0.1", scheme: "https", determined: true },
	};
};

/**
 * What the harness hands a grant: a test that calls the grant itself takes it, and replaces the
 * part it steps into.
 */
export function grantInput(
	issuing: Tokens,
	grant: Grant,
	client: Client,
	params: Readonly<Record<string, unknown>>,
	options: {
		readonly binding?: Binding;
		readonly request?: HttpRequest;
		readonly targets?: TargetRule;
	} = {},
	told: readonly SessionIssuance[] = [],
): GrantInput {
	const input = grantInputOf({
		request: sentRequest(params, grant.bodies?.[0] ?? "form"),
		client,
		grantType: grant.grantType,
		binding: options.binding,
		targets: options.targets ?? unread,
		tokens: issuing,
		told,
	});
	// A test that brings its own request replaces only the request, not how the parameters read.
	return options.request ? { ...input, request: options.request } : input;
}

/**
 * Calls a grant, for tests of the modules that contribute grants, in place of the token endpoint:
 * with a client, its parameters and a binding, as the endpoint would once it has authenticated
 * the client, allowed the grant and read the binding. Those three steps are the endpoint's own,
 * checked in its tests rather than here; a mistyped parameter and an untargeted request are refused
 * first, as the endpoint refuses them. Tests compose `client-allowance` beside it.
 */
export const grantCaller = defineModule({ name: "token-endpoint" }, (m) => [
	m.provide(targets).by(composedRule),
	m.provide(grantCalls).by(async (c) => {
		const known = await c.get(clients);
		const issuing = await c.get(tokens);
		const told = await c.collect(sessionIssuances);
		const table = new Map((await c.collect(grants)).map((grant) => [grant.grantType, grant]));
		const rule = await c.get(targets);
		return {
			call: async (grantType, clientId, params, options = {}) => {
				const grant = table.get(grantType);
				const client = await known.find(clientId);
				if (!grant || !client) throw new Error(`no grant ${grantType} or client ${clientId}`);
				const input = grantInput(
					issuing,
					grant,
					client,
					params,
					{ ...options, targets: rule },
					told,
				);
				// The endpoint's own checks before any grant runs, so a grant's declaration is tested too.
				const mistyped = mistypedRefusal(input.request);
				if (mistyped) return { kind: "error", ...mistyped };
				const untargeted = grant.targets ? undefined : rule.untargeted?.({ param: input.param });
				if (untargeted) return untargeted;
				const outcome = await grant.handle(input);
				if (outcome.kind === "refused") return refusedAnswer(outcome);
				return outcome.kind === "issued"
					? { ...outcome, body: answeredBody(outcome.body) }
					: outcome;
			},
		};
	}),
]);
