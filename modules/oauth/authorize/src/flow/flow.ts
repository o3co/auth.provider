import { type ClaimsSelections, claimsSelections } from "@mod/claims-selection";
import type { Client } from "@mod/clients";
import { type Codes, codeGrantType, codes } from "@mod/code-grant";
import { type BuildContext, type Clock, isUnavailable } from "@mod/kernel";
import { type Reauths, reauths as reauthsContract } from "@mod/reauth";
import { type Sessions, sessions } from "@mod/session";
import { type IssuanceRefused, type Tokens, tokens } from "@mod/tokens";
import {
	checkRequest,
	checkScope,
	type TargetCheck,
	targetCheckOver,
	targetCheckTakes,
} from "../checks/checks.ts";
import { claimsAsked, noClaims } from "../claims-request/claims-request.ts";
import {
	type ConsentDecision,
	consentDecisionOver,
	consentDecisionTakes,
} from "../consent-decision/consent-decision.ts";
import { type Again, type Decision, refusal } from "../decision.ts";
import { type HintCheck, hintCheckOver, hintCheckTakes } from "../hint/hint.ts";
import type { Settings } from "../section.ts";
import { type StepUp, stepUpOver, stepUpTakes } from "../step-up/step-up.ts";
import { urlFrom } from "../url.ts";

/** A refusal by an issuance policy: `access_denied` with its description, recorded with its name and reason. */
const policyRefusal = (refused: IssuanceRefused): Decision => ({
	kind: "refuse",
	error: "access_denied",
	...(refused.description ? { description: refused.description } : {}),
	reason: refused.reason,
	policy: refused.policy,
});

/** A request whose client and redirect URI are confirmed, as `route` read it. */
export interface Trusted {
	readonly client: Client;
	readonly redirectUri: string;
	/** A parameter's single value; none when it is repeated or too long. */
	readonly one: (name: string) => string | undefined;
	/** Each parameter's first value. */
	readonly params: ReadonlyMap<string, string>;
	/** The request itself, for the session it carries and every parameter value sent. */
	readonly request: Parameters<Sessions["enter"]>[0];
	/** A refusal `route` read in the request's form (a parameter repeated or too long): the flow's to answer. */
	readonly refused?: Decision;
}

/** The endpoint's own URL and the issuer's, both resolved by the package. */
export interface Place {
	readonly issuer: string;
	readonly self: string;
}

export interface FlowParts extends Place {
	readonly sessions: Pick<Sessions, "enter">;
	readonly codes: Pick<Codes, "issue" | "redemptionOf" | "lifetimeMs">;
	/** What a claims request names beyond its scope: read, selected and kept only while `on`. */
	readonly selections: Pick<ClaimsSelections, "scopeOf" | "select" | "keepForCode">;
	/** Whether a claims request's names and value constraints are taken (the package's `claims-parameter`). */
	readonly claimsParameter: boolean;
	/** Whether `tokens`' issuance policies would let the code's access token be issued. */
	readonly tokens: Pick<Tokens, "admits">;
	readonly clock: Clock;
	/** The package's `login-page`. */
	readonly loginPage: string;
	/** The longest login URL sent (the package's `login-url-limit`), in bytes. */
	readonly loginUrlLimit: number;
	/** Whether each request must name `openid` itself (the package's `oidc-mode`). */
	readonly openidRequired: boolean;
	readonly reauths: Reauths;
	readonly stepUp: StepUp;
	readonly consent: ConsentDecision;
	/** The audience a request asks for (`checks`, by `token-endpoint`'s composed rule). */
	readonly target: TargetCheck;
	/** The End-User an `id_token_hint` names (`hint`, by the reader contributed). */
	readonly hint: HintCheck;
}

/** A request whose login URL would be past the limit, answered here when it was not refused already. */
const tooLongToLogIn = refusal("invalid_request", "request too long to log in");

/** Decides for a trusted request: a refusal, a page to go to, or the code and its subject. */
export type Flow = (trusted: Trusted) => Promise<Decision>;

export function flowWith(parts: FlowParts): Flow {
	const { issuer, self, sessions: entered, codes: issued, clock, loginPage, loginUrlLimit } = parts;
	const { reauths, stepUp, consent, openidRequired, tokens: issuance, target: targetOf } = parts;
	const { selections, claimsParameter, hint: hintOf } = parts;
	const urlWith = urlFrom(self);

	/**
	 * The login page, `redirect_to` back to `back`, with the fresh login asked beside it; past the
	 * limit, `refused` (or a request too long to log in) answered here, nothing sent back.
	 */
	const sentToLogin = (
		back: string,
		fresh?: { readonly login: boolean; readonly maxAgeMs?: number | undefined },
		refused: Decision = tooLongToLogIn,
	): Decision => {
		const login = new URL(loginPage);
		login.searchParams.set("redirect_to", back);
		// The page hands these to a login it starts elsewhere, an upstream's, so that one is new too.
		if (fresh?.login) login.searchParams.set("prompt", "login");
		if (fresh?.maxAgeMs !== undefined)
			login.searchParams.set("max_age", String(fresh.maxAgeMs / 1000));
		if (login.href.length <= loginUrlLimit) return { kind: "send", to: login.href };
		if (refused.kind !== "refuse") return refused;
		const { error, description } = refused;
		return { kind: "answer", error, ...(description ? { description } : {}) };
	};

	// RFC 9700 §4.11.2: a refusal goes back only to a browser logged in, but for a silent request.
	const loggedInFirst = async (refused: Decision, { request }: Trusted): Promise<Decision> => {
		// Silent by any prompt sent, repeated or too long: such a request never shows a page.
		const silent = [...request.query].some(
			([name, values]) => name === "prompt" && values.some((v) => v.split(" ").includes("none")),
		);
		if (refused.kind !== "refuse" || silent) return refused;
		if (await entered.enter(request)) return refused;
		const sent = [...request.query].flatMap(([name, values]) =>
			values.map((v) => [name, v] as const),
		);
		return sentToLogin(urlWith(sent), undefined, refused);
	};

	/** The request read up to its session: a refusal, or what the rest of the flow decides on. */
	const readOf = async ({ client, one, params }: Trusted) => {
		const denied = consent.denied(one);
		if (denied) return denied;
		const checked = checkRequest(client, one, params);
		if (checked.kind !== "checked") return checked;
		const allowed = checkScope(client, one("scope"), issuer, openidRequired);
		if (allowed.kind !== "allowed") return allowed;
		// The names and the sub a claims request asks are OpenID Connect's alone, the names read only where
		// claims-parameter takes them and the sub whatever it says; an acr or auth_time asked holds for any request.
		const oidc = allowed.scope.includes("openid");
		const naming = oidc && claimsParameter;
		const claimsText = one("claims");
		const claims =
			claimsText === undefined
				? noClaims
				: claimsAsked(claimsText, naming ? selections.scopeOf : undefined, oidc);
		if (claims === "malformed") return refusal("invalid_request", "claims is malformed");
		// An id_token_hint, OpenID Connect's alone, asks a sub as a claims request does.
		const hinted = oidc ? await hintOf(one("id_token_hint")) : { kind: "hint" as const };
		if (hinted.kind !== "hint") return hinted;
		const subs = hinted.subject === undefined ? claims.subs : [...claims.subs, [hinted.subject]];
		const asked = stepUp.asked(one, params, claims);
		// A sub asked is checked first, once the session is known: an acr refusal waits for it.
		if (asked.kind !== "asked" && subs.length === 0) return asked;
		return { kind: "read", checked, allowed, claims, subs, asked } as const;
	};

	/** The request decided, `found` marked once its session is: an outage before then is never sent back. */
	const decided = async (trusted: Trusted, found: { session: boolean }): Promise<Decision> => {
		const { client, redirectUri, one, params, request } = trusted;
		const read = trusted.refused ?? (await readOf(trusted));
		if (read.kind !== "read") return loggedInFirst(read, trusted);
		const { checked, allowed, claims, subs, asked } = read;
		const { challenge, nonce, prompt } = checked;

		const without = (...names: string[]) => {
			const kept = new Map(params);
			for (const name of names) kept.delete(name);
			const left = [...prompt].filter((p) => !names.includes(`prompt:${p}`));
			if (left.length > 0) kept.set("prompt", left.join(" "));
			else kept.delete("prompt");
			return kept;
		};
		const again: Again = (names, add = []) => urlWith([...without(...names), ...add]);
		const need = {
			login: prompt.has("login"),
			maxAgeMs: checked.maxAgeMs,
			knownTime: claims.knownTime,
		};
		const toLogin = async (): Promise<Decision> => {
			if (prompt.has("none")) return refusal("login_required");
			const resume = without("reauth");
			if (need.login || need.maxAgeMs !== undefined || need.knownTime) {
				resume.set("reauth", await reauths.remember(params, clock.now()));
			}
			return sentToLogin(urlWith(resume), need);
		};
		const taken = await reauths.take(one("reauth"), params);
		// Back with a record that is not this request's (spent, unknown, or its demand taken out): never let through.
		if (params.has("reauth") && taken === undefined) {
			return loggedInFirst(refusal("login_required"), trusted);
		}

		const session = await entered.enter(request);
		if (!session) return toLogin();
		found.session = true;
		if (!reauths.fresh(need, session.context, taken)) {
			// Back from its login with a session still not new enough: another trip would bring the same.
			if (taken) return refusal("login_required");
			return toLogin();
		}
		// A sub asked by value names the only user the code may be for (OpenID Connect Core §3.1.2.2).
		if (!subs.every((values) => values.includes(session.context.subject))) {
			return refusal("login_required");
		}
		if (asked.kind !== "asked") return asked;
		const raised = await stepUp.met({
			acrs: asked.acrs,
			wanted: asked.wanted,
			essential: asked.essential,
			amr: session.context.amr,
			authenticatedAt: session.context.authenticatedAt,
			none: prompt.has("none"),
			taken,
			params,
			again,
		});
		if (raised.kind !== "met") return raised;
		const served = consent.served(client);
		if (served) return served;
		// Read now so the policies judge the code's audience; refused only after consent and them.
		const target = targetOf(client, one, allowed.audience, issuer);
		const { subject, amr, authenticatedAt, authenticatedAtUnknown } = session.context;
		const { scope } = allowed;
		// While the target is refused, the policies judge the default; its refusal comes after consent.
		const audience = target.kind === "audience" ? target.audience : allowed.audience;
		// Asked as the code's exchange will ask, so a refusal comes before consent and the code.
		const admitted = await issuance.admits({
			grant: {
				...{ subject, issuedTo: client.id, audience, scope, amr, authenticatedAt },
				...(authenticatedAtUnknown ? { authenticatedAtUnknown } : {}),
				...(raised.acr !== undefined ? { acr: raised.acr } : {}),
			},
			grantType: codeGrantType,
			session: session.id,
		});
		if (admitted.kind === "refused") return policyRefusal(admitted);
		const consented = await consent.decide(client, session, allowed.scope, prompt, again);
		if (consented) return consented;
		if (target.kind !== "audience") return target;
		// What an OpenID Connect request asks beyond its scope, cut to what is allowed and agreed to.
		const { idToken, userinfo } = claims.selection;
		const asksMore = [idToken, userinfo].some((t) => t.names.length + t.constraints.length > 0);
		const selection = asksMore
			? await selections.select(client, subject, claims.selection)
			: undefined;
		if (!reauths.fresh(need, session.context, taken)) {
			return taken ? refusal("login_required") : toLogin();
		}
		const code = await issued.issue({
			clientId: client.id,
			redirectUri,
			challenge,
			...(nonce !== undefined ? { nonce } : {}),
			scope: allowed.scope,
			audience: target.audience,
			session: session.id,
			subject: session.context.subject,
			...(raised.acr !== undefined ? { acr: raised.acr } : {}),
		});
		// Kept before the code goes out: one it cannot keep is never answered.
		if (selection) {
			await selections.keepForCode(issued.redemptionOf(code), selection, issued.lifetimeMs());
		}
		return { kind: "code", code, subject: session.context.subject };
	};

	return async (trusted) => {
		const found = { session: false };
		try {
			return await decided(trusted, found);
		} catch (error) {
			if (!isUnavailable(error) || found.session) throw error;
			return { kind: "unavailable", what: error.what };
		}
	};
}

/** What `flowOver` takes, its steps' included. */
export const flowTakes = [
	reauthsContract,
	sessions,
	codes,
	tokens,
	claimsSelections,
	...stepUpTakes,
	...consentDecisionTakes,
	...targetCheckTakes,
	...hintCheckTakes,
];

/** The steps over the contracts the assembly gives, each step built by its own module. */
export async function flowOver(c: BuildContext<Settings>, place: Place): Promise<Flow> {
	const reauths = await c.get(reauthsContract);
	return flowWith({
		...place,
		sessions: await c.get(sessions),
		codes: await c.get(codes),
		selections: await c.get(claimsSelections),
		tokens: await c.get(tokens),
		clock: c.clock,
		loginPage: c.section["login-page"],
		loginUrlLimit: c.section["login-url-limit"],
		openidRequired: c.section["oidc-mode"] === "oidc-required",
		claimsParameter: c.section["claims-parameter"],
		reauths,
		stepUp: await stepUpOver(c, reauths),
		consent: await consentDecisionOver(c),
		target: await targetCheckOver(c),
		hint: await hintCheckOver(c),
	});
}
