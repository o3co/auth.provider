import { createHash } from "node:crypto";
import type { Client } from "@mod/clients";
import type { Grant, GrantInput, GrantOutcome, TokenTie, TokenTieAnswer } from "@mod/grants";
import { Unavailable } from "@mod/kernel";
import { type Binding, carried } from "@mod/sender-binding";
import type { Actor, IssuedAccess, Tokens } from "@mod/tokens";
import { verified } from "./answer.ts";
import {
	accessTokenType,
	type Exchanged,
	type ExchangeVerifier,
	type OwnToken,
} from "./contract.ts";
import { targetWith } from "./target/target.ts";

export const grantType = "urn:ietf:params:oauth:grant-type:token-exchange";

export interface Parts {
	readonly verifiers: ReadonlyMap<string, ExchangeVerifier>;
	readonly tokens: Tokens;
	/** `grants`' token ties: what a token this provider issued is tied to, and joins one issued from it. */
	readonly ties: readonly TokenTie[];
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
/** What a presented token ends with besides itself: the earliest end of its ties, the session it came from, and the joins of one issued from it. */
interface Tie {
	readonly ends?: number;
	readonly session?: string;
	/** As grants types a held tie's `join`, so a change there reaches every call here. */
	readonly joins: readonly Extract<TokenTieAnswer, { kind: "held" }>["join"][];
}

const refused = (description: string, error = "invalid_request"): Refusal => ({
	kind: "error",
	error,
	description,
});
const isRefusal = (value: object): value is Refusal => "kind" in value && value.kind === "error";

/** A presented token must outlive the exchange by this much, or it is refused as expired. */
const expiryMarginMs = 1000;
/**
 * The request parameter asking a lifetime. RFC 6749 registers `expires_in` for answers alone, so the
 * one this provider adds carries its prefix (RFC 6749 §8.2); a request's `expires_in` is unknown, read
 * as nothing.
 */
const lifetimeParam = "o3co_expires_in";
/** A lifetime asked in `o3co_expires_in`: 1 to 10 ASCII digits, from 2. */
const lifetimeShape = /^[0-9]{1,10}$/;
/** The shortest lifetime `tokens` issues: one second, its iat cut to the second, leaves less than one. */
const minLifetimeSeconds = 2;

/** `o3co_expires_in` in seconds; none when left out or empty, NaN when malformed or under two. */
const askedLifetime = (value: string | undefined): number | undefined => {
	if (value === undefined || value === "") return undefined;
	const seconds = lifetimeShape.test(value) ? Number(value) : 0;
	return seconds >= minLifetimeSeconds ? seconds : Number.NaN;
};

const depthOf = (actor: Actor | undefined): number => (actor ? 1 + depthOf(actor.actor) : 0);

/** Whether the request proves by DPoP the key whose thumbprint's digest the subject token names. */
const holds = (binding: Binding | undefined, digest: string | undefined) =>
	binding?.tokenType === "DPoP" &&
	createHash("sha256").update(binding.confirmation, "ascii").digest("base64url") === digest;

/** Whether `may_act`, if the subject token has one, names the party acting; a client has no issuer. */
/** The token's own details where it has them: a foreign token holds none. */
const ownOf = (token: Exchanged | undefined): OwnToken | undefined =>
	token?.kind === "own" ? token : undefined;

const mayActFor = (subject: Exchanged, party: { readonly sub: string; readonly iss?: string }) =>
	subject.kind === "foreign" ||
	subject.mayAct === undefined ||
	subject.mayAct.some(
		({ sub, iss }) =>
			(sub !== undefined || iss !== undefined) &&
			(sub === undefined || sub === party.sub) &&
			(iss === undefined || iss === party.iss),
	);

export function exchangeGrant(parts: Parts): Grant {
	// In their names' order, so a family is read and joined before a session, however composed.
	const ties = parts.ties.toSorted((a, b) => (a.name < b.name ? -1 : 1));
	const { targetOf } = targetWith(parts.issuer);
	/** A token verified, unexpired, naming the client, or foreign and listing it; a once-only or foreign one never acts. */
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
		if (role === "actor" && (verifier.consume || answer.kind === "foreign"))
			return refused("actor_token cannot act");
		const named =
			answer.kind === "foreign"
				? answer.clients.includes(client.id)
				: answer.issuedTo === client.id ||
					answer.audience.includes(client.id) ||
					parts.othersTokens(client);
		if (!named) return refused(`${role}_token does not name this client`);
		return answer;
	};

	/** The ties a token of this provider has, read in their names' order, refused at the first ended. */
	const tieOf = async (role: Role, token: Exchanged): Promise<Tie | Refusal> => {
		if (token.kind === "foreign" || token.issued === undefined) return { joins: [] };
		let ends: number | undefined;
		let session: string | undefined;
		const joins: Tie["joins"][number][] = [];
		for (const tie of ties) {
			const answer = await tie.tieOf(token.issued);
			if (answer.kind === "none") continue;
			if (answer.kind === "ended") return refused(`${role}_token ${answer.reason}`);
			if (answer.ends !== undefined) ends = Math.min(ends ?? Infinity, answer.ends);
			// Two ties naming two sessions cannot both be what the token is issued from.
			if (answer.session !== undefined && session !== undefined && answer.session !== session) {
				throw new Unavailable("token-exchange");
			}
			session = answer.session ?? session;
			joins.push(answer.join);
		}
		return {
			...(ends === undefined ? {} : { ends }),
			...(session === undefined ? {} : { session }),
			joins,
		};
	};

	/**
	 * Joins the issued token, for the account it was issued to, to each of the subject token's ties in
	 * order; at the first that ended meanwhile, revokes it.
	 */
	const join = async (tie: Tie, issued: IssuedAccess, account: string) => {
		const reference = { id: issued.id, expiresAt: issued.expiresAt };
		for (const one of tie.joins) {
			if (await one(reference, account)) continue;
			// Its answer is not read: a tie may have revoked the token already.
			await parts.tokens.revokeAccess(issued.token);
			return false;
		}
		return true;
	};

	/** The holder, the binding, the actor chain, `may_act` and the target, in that order; a refusal stops them. */
	const policyOf = (input: GrantInput, subject: Exchanged, actor: Exchanged | undefined) => {
		// A public client has no secret: the key it proves must be the one the token was given for.
		const digest = subject.kind === "foreign" ? subject.holderDigest : undefined;
		if (input.client.kind !== "confidential" && !holds(input.binding, digest)) {
			return refused("the request does not prove the key the subject token names");
		}
		// issue binds the new token to the request's proof; this checks no binding is washed off.
		if (
			carried([ownOf(subject)?.binding, ownOf(actor)?.binding], input.binding).kind === "refused"
		) {
			return refused("the request does not prove the binding of the tokens presented");
		}
		const held = ownOf(subject)?.actor;
		const chain: Actor | undefined = actor && {
			subject: actor.subject,
			...(held ? { actor: held } : {}),
		};
		if (depthOf(chain) > parts.maxActorDepth) return refused("actor chain too deep");
		const party = actor ? { sub: actor.subject, iss: actor.issuer } : { sub: input.client.id };
		if (!mayActFor(subject, party)) return refused("may_act does not name the party acting");
		const target = targetOf(input, subject);
		if (isRefusal(target)) return target;
		return { chain, target };
	};

	/** The issued token's end: the subject token's, its ties', and the lifetime asked within the cap. */
	const expiryOf = (subject: Exchanged, tie: Tie, asked: number | undefined) => {
		const tieEnds = tie.ends ?? Infinity;
		// What was asked, cut to the operator's cap; without both, tokens' own lifetime caps it again.
		const cap = parts.maxLifetimeSeconds;
		const lifetime = Math.min(asked ?? Infinity, cap ?? Infinity);
		return {
			notAfter: Math.min(subject.expiresAt, tieEnds, parts.now() + lifetime * 1000),
			lifetimeSeconds: asked === undefined || cap === undefined ? undefined : lifetime,
		};
	};

	/** What the request asks, read and checked before any token is: the first that does not hold refuses it. */
	const readRequest = ({ client, param }: GrantInput) => {
		if (client.kind !== "confidential" && !parts.publicExchange(client)) {
			return { kind: "error", error: "invalid_client", status: 401 } satisfies Refusal;
		}
		const asked = askedLifetime(param(lifetimeParam));
		if (Number.isNaN(asked)) {
			return refused(`${lifetimeParam} must be a whole number of seconds from 2, in ASCII digits`);
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
		const actorParam = actorToken && actorType ? { token: actorToken, type: actorType } : undefined;
		return { asked, subjectToken, subjectType, actorParam };
	};

	return {
		grantType,
		readsAmbient: "none",
		// It reads `audience` and `resource` itself, by its own exact rule.
		targets: true,
		handle: async (input) => {
			const { client } = input;
			const request = readRequest(input);
			if (isRefusal(request)) return request;
			const { asked, subjectToken, subjectType, actorParam } = request;

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
			const own = ownOf(subject);
			const access = {
				subject: subject.subject,
				issuedTo: client.id,
				// It stands where the subject token does, never from its own issue.
				standingAt: subject.standingAt,
				...target,
				...(chain ? { actor: chain } : {}),
				...(own?.amr ? { amr: own.amr } : {}),
				...(own?.authenticatedAt === undefined ? {} : { authenticatedAt: own.authenticatedAt }),
				...(own?.acr === undefined ? {} : { acr: own.acr }),
			};
			const from = tie.session ? { session: tie.session } : {};
			const allowed = await input.issue(access, {
				notAfter,
				...(lifetimeSeconds === undefined ? {} : { lifetimeSeconds }),
				...from,
			});
			if (allowed.kind === "refused") return allowed;
			const issued = allowed.access;
			if (!(await join(tie, issued, access.subject))) return refused("subject_token has ended");
			// A once-only token is used up last, once its token is issued, so a refusal or a failure
			// before leaves it usable. That token is never handed out unless it was used up here; one
			// whose revocation fails is held by no one.
			const verifier = parts.verifiers.get(subjectType);
			if (verifier?.consume) {
				const withdrawn = () => parts.tokens.revokeAccess(issued.token).catch(() => undefined);
				const used = await verifier.consume(subjectToken).catch(async (error: unknown) => {
					await withdrawn();
					throw error;
				});
				if (used !== "consumed") {
					await withdrawn();
					if (used === "replayed") return refused("subject_token has been used");
					throw new Unavailable("token-exchange");
				}
			}
			return {
				kind: "issued",
				body: {
					access_token: issued.token,
					issued_token_type: accessTokenType,
					token_type: issued.tokenType,
					expires_in: issued.expiresIn,
					scope: target.scope.join(" "),
				},
			};
		},
	};
}
