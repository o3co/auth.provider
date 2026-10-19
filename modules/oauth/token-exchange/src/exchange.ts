import { createHash } from "node:crypto";
import { clientAllowance } from "@mod/client-allowance";
import type { Client } from "@mod/clients";
import type { Grant, GrantInput, GrantOutcome } from "@mod/grants";
import { Unavailable } from "@mod/kernel";
import type { FamilyHandle, Lineage } from "@mod/refresh";
import { type Binding, carried } from "@mod/sender-binding";
import type { Sessions } from "@mod/session";
import type { SessionTokens } from "@mod/session-tokens";
import type { Actor, IssuedAccess, Tokens } from "@mod/tokens";
import { verified } from "./answer.ts";
import { accessTokenType, type Exchanged, type ExchangeVerifier } from "./contract.ts";

export const grantType = "urn:ietf:params:oauth:grant-type:token-exchange";

export interface Parts {
	readonly verifiers: ReadonlyMap<string, ExchangeVerifier>;
	readonly tokens: Tokens;
	readonly lineage: Lineage;
	readonly sessionTokens: Pick<SessionTokens, "sessionOf">;
	readonly sessions: Sessions;
	readonly issuer: string;
	readonly maxActorDepth: number;
	/** The operator's cap on an issued token's lifetime, in seconds; tokens' lifetime bounds it too. */
	readonly maxLifetimeSeconds?: number;
	readonly othersTokens: (client: Client) => boolean;
	/** Whether a public client may exchange, holding by DPoP the key the subject token names. */
	readonly publicExchange: (client: Client) => boolean;
	readonly now: () => number;
}

type Refusal = Extract<GrantOutcome, { kind: "error" }>;
type Role = "subject" | "actor";
/** What a presented token ends with: its family (and the session it came from), its session, or itself alone. */
type Tie =
	| {
			readonly kind: "family";
			readonly family: FamilyHandle;
			readonly ends: number;
			readonly session?: string;
	  }
	| { readonly kind: "session"; readonly session: string }
	| { readonly kind: "alone" };

const refused = (description: string, error = "invalid_request"): Refusal => ({
	kind: "error",
	error,
	description,
});
const isRefusal = (value: object): value is Refusal => "kind" in value && value.kind === "error";

/** A presented token must outlive the exchange by this much, or it is refused as expired. */
const expiryMarginMs = 1000;
/** A lifetime asked in `expires_in`: 1 to 10 ASCII digits, above zero. */
const lifetimeShape = /^[0-9]{1,10}$/;

/** `expires_in` in seconds; none when left out or empty, NaN when malformed. */
const askedLifetime = (value: string | undefined): number | undefined => {
	if (value === undefined || value === "") return undefined;
	const seconds = lifetimeShape.test(value) ? Number(value) : 0;
	return seconds > 0 ? seconds : Number.NaN;
};

const depthOf = (actor: Actor | undefined): number => (actor ? 1 + depthOf(actor.actor) : 0);

/** Whether the request proves by DPoP the key whose thumbprint's digest the subject token names. */
const holds = (binding: Binding | undefined, digest: string | undefined) =>
	binding?.tokenType === "DPoP" &&
	createHash("sha256").update(binding.confirmation, "ascii").digest("base64url") === digest;

/** Whether `may_act`, if the subject token has one, names the party acting; a client has no issuer. */
const mayActFor = (subject: Exchanged, party: { readonly sub: string; readonly iss?: string }) =>
	subject.mayAct === undefined ||
	subject.mayAct.some(
		({ sub, iss }) =>
			(sub !== undefined || iss !== undefined) &&
			(sub === undefined || sub === party.sub) &&
			(iss === undefined || iss === party.iss),
	);

export function exchangeGrant(parts: Parts): Grant {
	/** A token verified, unexpired, naming the client or listing it in `clients`; a once-only or client-ceiling one never acts. */
	const presented = async (
		client: Client,
		role: Role,
		token: string,
		type: string,
	): Promise<Exchanged | Refusal> => {
		const verifier = parts.verifiers.get(type);
		if (!verifier) return refused(`${role}_token_type is not supported`);
		const answer = await verified(verifier, token);
		if (!answer) return refused(`${role}_token validation failed`);
		if (answer.expiresAt - parts.now() < expiryMarginMs)
			return refused(`${role}_token has expired`);
		if (role === "actor" && (verifier.consume || answer.ceiling))
			return refused("actor_token cannot act");
		const named = answer.clients
			? answer.clients.includes(client.id)
			: answer.issuedTo === client.id ||
				answer.audience.includes(client.id) ||
				parts.othersTokens(client);
		if (!named) return refused(`${role}_token does not name this client`);
		return answer;
	};

	/** The family and session a token of this provider ends with, refused once either has ended. */
	const tieOf = async (role: Role, token: Exchanged): Promise<Tie | Refusal> => {
		if (token.issued === undefined) return { kind: "alone" };
		const family = await parts.lineage.of(token.issued);
		if (family.kind === "ended") return refused(`${role}_token family has ended`);
		// A family's token is recorded to its session too: the policies hear of it on either path.
		const bound = await parts.sessionTokens.sessionOf(token.issued);
		if (bound.kind === "bound") {
			const entry = await parts.sessions.entryOf(bound.handle);
			if (entry.kind === "absent") return refused(`${role}_token session has ended`);
			if (entry.kind === "short") return refused(`${role}_token session is short of a requirement`);
		}
		const session = bound.kind === "bound" ? bound.handle : undefined;
		if (family.kind === "family") {
			const ends = family.expiresAt;
			return { kind: "family", family: family.family, ends, ...(session ? { session } : {}) };
		}
		return session === undefined ? { kind: "alone" } : { kind: "session", session };
	};

	/** The scope and the one audience asked for, within the client's allowance alone. */
	const clientTargetOf = ({ client, param }: GrantInput) => {
		const allowed = clientAllowance.allowedIssuance(client, param("scope"), parts.issuer);
		if (allowed.kind === "error") {
			return refused(allowed.description ?? "scope is not within the client's", allowed.error);
		}
		const audience = param("audience") || allowed.audience[0];
		if (audience === undefined || !clientAllowance.allowsAudience(client, audience, parts.issuer)) {
			return refused("audience is not one the client may be issued", "invalid_target");
		}
		const resource = param("resource");
		if (resource && resource !== audience) {
			return refused("resource is not the audience issued", "invalid_target");
		}
		return { scope: [...allowed.scope], audience: [audience] };
	};

	/** The scope and the one audience asked for, within the subject token's and the client's. */
	const targetOf = (input: GrantInput, subject: Exchanged) => {
		if (subject.ceiling === "client") return clientTargetOf(input);
		const { client, param } = input;
		const allows = (scope: string) => clientAllowance.allowsScope(client, scope);
		const asked = clientAllowance.parseScope(param("scope"));
		const ceiling = [...new Set(subject.scope.filter(allows))];
		if (!asked || asked.some((s) => !ceiling.includes(s))) {
			return refused("scope is not within the subject token's and the client's", "invalid_scope");
		}
		const held = subject.audience.filter((a) =>
			clientAllowance.allowsAudience(client, a, parts.issuer),
		);
		const audience = param("audience") || (held.length === 1 ? held[0] : undefined);
		if (audience === undefined || !held.includes(audience)) {
			return refused("audience is not one the subject token and the client hold", "invalid_target");
		}
		const resource = param("resource");
		if (resource && resource !== audience) {
			return refused("resource is not the audience issued", "invalid_target");
		}
		return { scope: asked.length > 0 ? [...new Set(asked)] : ceiling, audience: [audience] };
	};

	/** Joins the issued token to the subject's family and session; false when either ended meanwhile. */
	const join = async (tie: Tie, issued: IssuedAccess) => {
		const reference = { id: issued.id, expiresAt: issued.expiresAt };
		if (tie.kind === "alone") return true;
		// lineage revokes a token it does not adopt.
		if (tie.kind === "family" && (await parts.lineage.adopt(tie.family, reference)) !== "adopted") {
			return false;
		}
		// A logout that came while the token was being issued and recorded voids it.
		if (tie.session === undefined) return true;
		if ((await parts.sessions.entryOf(tie.session)).kind === "entered") return true;
		await parts.tokens.revokeAccess(issued.token);
		return false;
	};

	/** The holder, the binding, the actor chain, `may_act` and the target, in that order; a refusal stops them. */
	const policyOf = (input: GrantInput, subject: Exchanged, actor: Exchanged | undefined) => {
		// A public client has no secret: the key it proves must be the one the token was given for.
		if (input.client.kind !== "confidential" && !holds(input.binding, subject.holderDigest)) {
			return refused("the request does not prove the key the subject token names");
		}
		// issue binds the new token to the request's proof; this checks no binding is washed off.
		if (carried([subject.binding, actor?.binding], input.binding).kind === "refused") {
			return refused("the request does not prove the binding of the tokens presented");
		}
		const chain: Actor | undefined = actor && {
			subject: actor.subject,
			...(subject.actor ? { actor: subject.actor } : {}),
		};
		if (depthOf(chain) > parts.maxActorDepth) return refused("actor chain too deep");
		const party = actor ? { sub: actor.subject, iss: actor.issuer } : { sub: input.client.id };
		if (!mayActFor(subject, party)) return refused("may_act does not name the party acting");
		const target = targetOf(input, subject);
		if (isRefusal(target)) return target;
		return { chain, target };
	};

	/** The issued token's end: the subject token's, its family's, and the lifetime asked within the cap. */
	const expiryOf = (subject: Exchanged, tie: Tie, asked: number | undefined) => {
		const familyEnds = tie.kind === "family" ? tie.ends : Infinity;
		// What was asked, cut to the operator's cap; without both, tokens' own lifetime caps it again.
		const cap = parts.maxLifetimeSeconds;
		const lifetime = Math.min(asked ?? Infinity, cap ?? Infinity);
		return {
			notAfter: Math.min(subject.expiresAt, familyEnds, parts.now() + lifetime * 1000),
			lifetimeSeconds: asked === undefined || cap === undefined ? undefined : lifetime,
		};
	};

	return {
		grantType,
		readsAmbient: "none",
		// It reads `audience` and `resource` itself, by its own exact rule.
		targets: true,
		handle: async (input) => {
			const { client, param } = input;
			if (client.kind !== "confidential" && !parts.publicExchange(client)) {
				return { kind: "error", error: "invalid_client", status: 401 };
			}
			const asked = askedLifetime(param("expires_in"));
			if (Number.isNaN(asked)) {
				return refused("expires_in must be a positive whole number of seconds in ASCII digits");
			}
			const requested = param("requested_token_type");
			if (requested !== undefined && requested !== accessTokenType) {
				return refused("requested_token_type is not supported");
			}
			const [subjectToken, subjectType] = [param("subject_token"), param("subject_token_type")];
			const [actorToken, actorType] = [param("actor_token"), param("actor_token_type")];
			if (!subjectToken || !subjectType) {
				return refused("subject_token and subject_token_type are required");
			}
			if (Boolean(actorToken) !== Boolean(actorType)) {
				return refused("actor_token and actor_token_type go together");
			}
			const actorParam =
				actorToken && actorType ? { token: actorToken, type: actorType } : undefined;

			const check = async () => {
				const subject = await presented(client, "subject", subjectToken, subjectType);
				if (isRefusal(subject)) return subject;
				const actor =
					actorParam && (await presented(client, "actor", actorParam.token, actorParam.type));
				if (actor && isRefusal(actor)) return actor;
				const tie = await tieOf("subject", subject);
				if (isRefusal(tie)) return tie;
				const actorTie = actor && (await tieOf("actor", actor));
				if (actorTie && isRefusal(actorTie)) return actorTie;
				return { subject, actor, tie };
			};
			const first = await check();
			if (isRefusal(first)) return first;
			const { subject, actor } = first;
			const policy = policyOf(input, subject, actor);
			if (isRefusal(policy)) return policy;
			const { chain, target } = policy;

			// Checked again last, so a revocation or a logout in the meantime is seen. What is issued
			// comes from the first answers; only the tie, which can change meanwhile, is taken from here.
			const last = await check();
			if (isRefusal(last)) return last;
			const { tie } = last;
			const { notAfter, lifetimeSeconds } = expiryOf(subject, tie, asked);
			const access = {
				subject: subject.subject,
				issuedTo: client.id,
				...target,
				...(chain ? { actor: chain } : {}),
				...(subject.amr ? { amr: subject.amr } : {}),
				...(subject.authenticatedAt === undefined
					? {}
					: { authenticatedAt: subject.authenticatedAt }),
				...(subject.acr === undefined ? {} : { acr: subject.acr }),
			};
			const from = tie.kind !== "alone" && tie.session ? { session: tie.session } : {};
			// A once-only token is used up last: after the policies' leave, so a refusal leaves it usable.
			const verifier = parts.verifiers.get(subjectType);
			if (verifier?.consume) {
				const admitted = await input.admits(access, from);
				if (admitted.kind === "refused") return admitted;
				const used = await verifier.consume(subjectToken);
				if (used === "replayed") return refused("subject_token has been used");
				if (used !== "consumed") throw new Unavailable("token-exchange");
			}
			const allowed = await input.issue(access, {
				notAfter,
				...(lifetimeSeconds === undefined ? {} : { lifetimeSeconds }),
				...from,
			});
			if (allowed.kind === "refused") return allowed;
			const issued = allowed.access;
			if (!(await join(tie, issued))) return refused("subject_token has ended");
			return {
				kind: "issued",
				body: {
					access_token: issued.token,
					issued_token_type: accessTokenType,
					token_type: issued.tokenType,
					expires_in: issued.expiresIn,
					...(target.scope.length > 0 ? { scope: target.scope.join(" ") } : {}),
				},
			};
		},
	};
}
