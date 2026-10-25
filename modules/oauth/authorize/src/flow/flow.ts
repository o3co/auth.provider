import type { Client } from "@mod/clients";
import { type Codes, codeGrantType, codes } from "@mod/code-grant";
import type { BuildContext, Clock } from "@mod/kernel";
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
import {
	type ConsentDecision,
	consentDecisionOver,
	consentDecisionTakes,
} from "../consent-decision/consent-decision.ts";
import { type Again, type Decision, refusal } from "../decision.ts";
import type { Settings } from "../section.ts";
import { type StepUp, stepUpOver, stepUpTakes } from "../step-up/step-up.ts";

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
	/** The request itself, for the session it carries. */
	readonly request: Parameters<Sessions["enter"]>[0];
}

/** The endpoint's own URL and the issuer's, both resolved by the package. */
export interface Place {
	readonly issuer: string;
	readonly self: string;
}

export interface FlowParts extends Place {
	readonly sessions: Pick<Sessions, "enter">;
	readonly codes: Pick<Codes, "issue">;
	/** Whether `tokens`' issuance policies would let the code's access token be issued. */
	readonly tokens: Pick<Tokens, "admits">;
	readonly clock: Clock;
	/** The package's `login-page`. */
	readonly loginPage: string;
	/** Whether each request must name `openid` itself (the package's `oidc-mode`). */
	readonly openidRequired: boolean;
	readonly reauths: Reauths;
	readonly stepUp: StepUp;
	readonly consent: ConsentDecision;
	/** The audience a request asks for (`checks`, by `token-endpoint`'s composed rule). */
	readonly target: TargetCheck;
}

/** Decides for a trusted request: a refusal, a page to go to, or the code and its subject. */
export type Flow = (trusted: Trusted) => Promise<Decision>;

export function flowWith(parts: FlowParts): Flow {
	const { issuer, self, sessions: entered, codes: issued, clock, loginPage } = parts;
	const { reauths, stepUp, consent, openidRequired, tokens: issuance, target: targetOf } = parts;
	const urlWith = (params: Iterable<readonly [string, string]>) =>
		`${self}?${new URLSearchParams([...params].map(([k, v]) => [k, v]))}`;

	return async ({ client, redirectUri, one, params, request }) => {
		const denied = consent.denied(one);
		if (denied) return denied;
		const checked = checkRequest(client, one, params);
		if (checked.kind !== "checked") return checked;
		const { challenge, nonce, prompt } = checked;
		const asked = stepUp.asked(one, params);
		if (asked.kind !== "asked") return asked;
		const allowed = checkScope(client, one("scope"), issuer, openidRequired);
		if (allowed.kind !== "allowed") return allowed;

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
			knownTime: asked.knownTime,
		};
		const toLogin = async (): Promise<Decision> => {
			if (prompt.has("none")) return refusal("login_required");
			const resume = without("reauth");
			if (need.login || need.maxAgeMs !== undefined || need.knownTime) {
				resume.set("reauth", await reauths.remember(params, clock.now()));
			}
			const login = new URL(loginPage);
			login.searchParams.set("redirect_to", urlWith(resume));
			// The page hands these to a login it starts elsewhere, an upstream's, so that one is new too.
			if (need.login) login.searchParams.set("prompt", "login");
			if (need.maxAgeMs !== undefined)
				login.searchParams.set("max_age", String(need.maxAgeMs / 1000));
			return { kind: "send", to: login.href };
		};
		const taken = await reauths.take(one("reauth"), params);
		// Back with a record that is not this request's (spent, unknown, or its demand taken out): never let through.
		if (params.has("reauth") && taken === undefined) return refusal("login_required");

		const session = await entered.enter(request);
		if (!session) return toLogin();
		if (!reauths.fresh(need, session.context, taken)) {
			// Back from its login with a session still not new enough: another trip would bring the same.
			if (taken) return refusal("login_required");
			return toLogin();
		}
		const raised = await stepUp.met({
			acrs: asked.acrs,
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
		return { kind: "code", code, subject: session.context.subject };
	};
}

/** The steps over the contracts the assembly gives, each step built by its own module. */
/** What `flowOver` takes, its steps' included. */
export const flowTakes = [
	reauthsContract,
	sessions,
	codes,
	tokens,
	...stepUpTakes,
	...consentDecisionTakes,
	...targetCheckTakes,
];

export async function flowOver(c: BuildContext<Settings>, place: Place): Promise<Flow> {
	const reauths = await c.get(reauthsContract);
	return flowWith({
		...place,
		sessions: await c.get(sessions),
		codes: await c.get(codes),
		tokens: await c.get(tokens),
		clock: c.clock,
		loginPage: c.section["login-page"],
		openidRequired: c.section["oidc-mode"] === "oidc-required",
		reauths,
		stepUp: await stepUpOver(c, reauths),
		consent: await consentDecisionOver(c),
		target: await targetCheckOver(c),
	});
}
