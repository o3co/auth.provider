import { defineModule, isUnavailable, Unavailable } from "@mod/kernel";
import { type Binding, senderBindings } from "@mod/sender-binding";
import { denylistAllowanceMs, denylistOver } from "@mod/token-denylist";
import { describe, expect, it } from "vitest";
import type { z } from "zod";
import {
	type AccessCheck,
	type AccessGrant,
	type Actor,
	accessConditions,
	type IssuancePolicy,
	type IssuanceVerdict,
	type IssueLimits,
	issuancePolicies,
	referenceOf,
	subjectChecks,
	type Tokens,
	tokens,
} from "./contract.ts";
import { authenticatedAheadMs, type IssueAccess, issuing, judging } from "./issuance/issuance.ts";
import { defaultLifetimeSeconds, expiryOf, keptGrant, lifetimeOf, tokenId } from "./limits.ts";
import { namedBy } from "./reference.ts";
import type { section } from "./section.ts";

export type TokensSettings = z.input<typeof section>;

/**
 * A tokens section for tests. Unless the composition checks subjects (it includes the module
 * that does), it states that no module checks subject revocation, as tokens then requires.
 */
export function tokensConfig(
	settings: Partial<TokensSettings> = {},
	{ subjects = "unchecked" }: { readonly subjects?: "checked" | "unchecked" } = {},
) {
	const stated = subjects === "unchecked" ? { "subject-check": "none" as const } : {};
	return {
		tokens: { revocation: "unsupported", ...stated, ...settings },
	};
}

/** A composition that offers tokens, as one implementation of the contract does. */
export interface TokensUnderTest {
	readonly tokens: Tokens;
	/** The time tokens are judged by now, and a way to move it on. */
	now(): number;
	advance(ms: number): void;
	/** A binding kind the composition knows: the `cnf` member it writes, and its token type. */
	readonly known: { readonly member: string; readonly tokenType: string };
	/** From now on, the composition's subject check answers revoked for this subject. */
	revokeSubject(subject: string): void;
}

/**
 * What every implementation of tokens' contract must do, as a caller sees it. Signatures and the
 * allowance past expiry are tokens' own, checked in its tests rather than here.
 */
export function tokensContract(
	name: string,
	open: (options: {
		readonly revocable: boolean;
		/** Issuance policies the composition contributes. */
		readonly policies?: readonly IssuancePolicy[];
		/** The access-token lifetime the composition is configured with; the section's default where absent. */
		readonly lifetimeSeconds?: number;
	}) => Promise<TokensUnderTest>,
): void {
	const grant = { subject: "s", issuedTo: "c", audience: ["api"], scope: ["read"] };
	/** An actor chain n deep. */
	const chain = (n: number): Actor =>
		n === 1 ? { subject: "a1" } : { subject: `a${n}`, actor: chain(n - 1) };
	/** Issues through `issue`, which no policy here refuses, and answers what it issued. */
	const issueFor = async (tokens: Tokens, grant: AccessGrant, limits?: IssueLimits) => {
		const issued = await tokens.issue({ grant, grantType: "test" }, limits);
		if (issued.kind !== "issued") throw new Error(`refused by ${issued.policy}`);
		return issued.access;
	};
	const allowing: IssuancePolicy = { name: "allows", judge: async () => ({ kind: "allowed" }) };
	describe(`tokens' contract: ${name}`, () => {
		it("issues a token that verifies as issued until exactly its expiry", async () => {
			const place = await open({ revocable: true });
			const issued = await issueFor(place.tokens, grant);
			expect(issued.tokenType).toBe("Bearer");
			expect(issued.expiresIn).toBeGreaterThan(0);
			expect(await place.tokens.verifyAccess(issued.token)).toMatchObject({
				kind: "valid",
				grant,
				expiresAt: issued.expiresAt,
				tokenType: "Bearer",
			});
			place.advance(issued.expiresAt - place.now() - 1);
			expect((await place.tokens.verifyAccess(issued.token)).kind).toBe("valid");
			place.advance(1);
			expect(await place.tokens.verifyAccess(issued.token)).toEqual({
				kind: "invalid",
				reason: "expired",
			});
			expect((await place.tokens.verifyAccess("not a token")).kind).toBe("invalid");
		});

		it("answers the id it issued, and the actor, amr and authentication time (to the second) only where given", async () => {
			const place = await open({ revocable: true });
			const plain = await issueFor(place.tokens, grant);
			const checked = await place.tokens.verifyAccess(plain.token);
			expect(checked.kind === "valid" && checked.id).toBe(plain.id);
			expect(checked.kind === "valid" && checked.grant).toStrictEqual(grant);
			const second = Math.floor(place.now() / 1000) * 1000 - 60_000;
			const full = {
				...grant,
				actor: { subject: "a", actor: { subject: "b" } },
				amr: ["hwk"],
			};
			const issued = await issueFor(place.tokens, { ...full, authenticatedAt: second + 999 });
			expect(issued.id).not.toBe(plain.id);
			expect(await place.tokens.verifyAccess(issued.token)).toMatchObject({
				kind: "valid",
				id: issued.id,
				grant: { ...full, authenticatedAt: second },
			});
		});

		it("answers no authentication time where the grant says it is not known", async () => {
			const place = await open({ revocable: true });
			const unknown = {
				...grant,
				authenticatedAt: place.now(),
				authenticatedAtUnknown: true as const,
			};
			const issued = await issueFor(place.tokens, unknown);
			const read = await place.tokens.verifyAccess(issued.token);
			expect(read.kind === "valid" && read.grant).toStrictEqual(grant);
		});

		it("takes an empty amr as none, and carries acr only where given", async () => {
			const place = await open({ revocable: true });
			const empty = await issueFor(place.tokens, { ...grant, amr: [] });
			const read = await place.tokens.verifyAccess(empty.token);
			expect(read.kind === "valid" && read.grant).toStrictEqual(grant);
			const asked = await issueFor(place.tokens, { ...grant, acr: "urn:example:acr:high" });
			expect(await place.tokens.verifyAccess(asked.token)).toMatchObject({
				kind: "valid",
				grant: { ...grant, acr: "urn:example:acr:high" },
			});
		});

		it("takes an authentication time a little ahead of the clock as the time it issues", async () => {
			const place = await open({ revocable: true });
			const issuedAt = Math.floor(place.now() / 1000) * 1000;
			const ahead = await issueFor(place.tokens, {
				...grant,
				authenticatedAt: place.now() + 60_000,
			});
			expect(await place.tokens.verifyAccess(ahead.token)).toMatchObject({
				kind: "valid",
				grant: { authenticatedAt: issuedAt },
			});
		});

		it("issues where no policy refuses, the same token for any grant type, and admits alike", async () => {
			const place = await open({ revocable: true, policies: [allowing] });
			const request = { grant, grantType: "client_credentials" };
			expect(await place.tokens.admits(request)).toEqual({ kind: "allowed" });
			const issued = await place.tokens.issue(request);
			if (issued.kind !== "issued") throw new Error("refused");
			const other = await issueFor(place.tokens, grant);
			const { expiresAt, expiresIn } = issued.access;
			expect(issued.access.tokenType).toBe("Bearer");
			expect(other).toMatchObject({ expiresAt, expiresIn, tokenType: "Bearer" });
			expect(await place.tokens.verifyAccess(issued.access.token)).toMatchObject({
				kind: "valid",
				id: issued.access.id,
				grant,
				expiresAt: issued.access.expiresAt,
			});
		});

		it("asks the policies in name order and issues nothing at the first refusal", async () => {
			const asked: string[] = [];
			const policy = (name: string, refuse: boolean): IssuancePolicy => ({
				name,
				judge: async () => {
					asked.push(name);
					return refuse
						? { kind: "refused", reason: `${name}_said_no`, description: `${name} said no` }
						: { kind: "allowed" };
				},
			});
			const place = await open({
				revocable: true,
				policies: [policy("c", true), policy("a", false), policy("b", true)],
			});
			const request = { grant, grantType: "authorization_code", session: "s1" };
			const refused = {
				kind: "refused",
				policy: "b",
				reason: "b_said_no",
				description: "b said no",
			};
			expect(await place.tokens.issue(request)).toEqual(refused);
			expect(asked).toEqual(["a", "b"]);
			expect(await place.tokens.admits(request)).toEqual(refused);
		});

		it("hands the policies the request as given, a continuing issuance marked so", async () => {
			const seen: unknown[] = [];
			const watching: IssuancePolicy = {
				name: "watching",
				judge: async (request) => {
					seen.push(request.continuing);
					return { kind: "allowed" };
				},
			};
			const place = await open({ revocable: true, policies: [watching] });
			await place.tokens.issue({ grant, grantType: "refresh_token", continuing: true });
			await place.tokens.admits({ grant, grantType: "authorization_code" });
			expect(seen).toEqual([true, undefined]);
		});

		it("signs the grant and limits the policies judged, though the caller changes its own while they judge", async () => {
			let release: () => void = () => {};
			const asked = new Promise<void>((done) => {
				release = done;
			});
			let judging: () => void = () => {};
			const judged = new Promise<void>((done) => {
				judging = done;
			});
			const slow: IssuancePolicy = {
				name: "slow",
				judge: async () => {
					judging();
					await asked;
					return { kind: "allowed" };
				},
			};
			const place = await open({ revocable: true, policies: [slow] });
			const own = { ...grant, audience: [...grant.audience], scope: [...grant.scope] };
			const limits = { lifetimeSeconds: 60 };
			const issuing = place.tokens.issue({ grant: own, grantType: "test" }, limits);
			await judged;
			// The caller's own objects, changed after the policies were asked and before the signing.
			Object.assign(own, { subject: "mallory" });
			own.scope.push("admin");
			Object.assign(limits, { lifetimeSeconds: 86_400 });
			release();
			const issued = await issuing;
			if (issued.kind !== "issued") throw new Error(issued.policy);
			expect(issued.access.expiresIn).toBe(60);
			expect(await place.tokens.verifyAccess(issued.access.token)).toMatchObject({
				kind: "valid",
				grant: { subject: "s", scope: ["read"] },
			});
		});

		it("carries the claims a grant adds, read back frozen and named in name order, and refuses a reserved one", async () => {
			const place = await open({ revocable: true });
			const claims = { b: { c: [1] }, a: "x" };
			const issued = await place.tokens.issue({ grant: { ...grant, claims }, grantType: "test" });
			if (issued.kind !== "issued") throw new Error(issued.policy);
			expect(issued.access.addedClaims).toEqual(["a", "b"]);
			const checked = await place.tokens.verifyAccess(issued.access.token);
			if (checked.kind !== "valid") throw new Error(checked.reason);
			expect(checked.grant.claims).toEqual(claims);
			expect(Object.isFrozen(checked.grant.claims?.b)).toBe(true);
			const plain = await issueFor(place.tokens, grant);
			expect("addedClaims" in plain).toBe(false);
			const reserved = { grant: { ...grant, claims: { scope: "x" } }, grantType: "test" };
			await expect(place.tokens.issue(reserved)).rejects.toThrow(TypeError);
			await expect(place.tokens.admits(reserved)).rejects.toThrow(TypeError);
		});

		it("reads back the added claims frozen at every depth, and their names frozen", async () => {
			const place = await open({ revocable: true });
			const claims = { a: { b: [{ c: [1] }] } };
			const issued = await place.tokens.issue({ grant: { ...grant, claims }, grantType: "test" });
			if (issued.kind !== "issued") throw new Error(issued.policy);
			expect(Object.isFrozen(issued.access.addedClaims)).toBe(true);
			const checked = await place.tokens.verifyAccess(issued.access.token);
			const read = checked.kind === "valid" ? checked.grant.claims : undefined;
			const levels = [read, read?.a, (read?.a as { b: unknown })?.b];
			const inner = (levels[2] as readonly { c: unknown }[] | undefined)?.[0];
			for (const level of [...levels, inner, inner?.c]) expect(Object.isFrozen(level)).toBe(true);
		});

		it("refuses every reserved name at the top, at issue and at admits, and takes each one nested", async () => {
			const place = await open({ revocable: true });
			// Written as the rules name them, so dropping one from the rules fails here.
			const names = [
				...["iss", "sub", "aud", "client_id", "scope", "act", "amr", "auth_time", "acr", "iat"],
				...["exp", "jti", "cnf", "nbf", "roles", "groups", "entitlements", "scp", "may_act"],
				...["authorization_details", "htm", "htu", "ath", "nonce", "azp", "at_hash", "c_hash"],
				...["sid", "name", "picture", "profile", "email", "email_verified", "active"],
				...["token_type", "username"],
			];
			for (const name of names) {
				const request = { grant: { ...grant, claims: { [name]: 1 } }, grantType: "test" };
				await expect(place.tokens.issue(request), name).rejects.toThrow(TypeError);
				await expect(place.tokens.admits(request), name).rejects.toThrow(TypeError);
			}
			const nested = Object.fromEntries(names.map((name) => [name, 1]));
			const taken = { grant: { ...grant, claims: { nested } }, grantType: "test" };
			expect((await place.tokens.issue(taken)).kind).toBe("issued");
		});

		it("issues and reads back an actor chain 16 deep, and refuses one of 17 as the caller's mistake", async () => {
			const place = await open({ revocable: true });
			const deepest = await issueFor(place.tokens, { ...grant, actor: chain(16) });
			expect(await place.tokens.verifyAccess(deepest.token)).toMatchObject({
				kind: "valid",
				grant: { actor: chain(16) },
			});
			const over = { grant: { ...grant, actor: chain(17) }, grantType: "test" };
			await expect(place.tokens.issue(over)).rejects.toThrow(TypeError);
			await expect(place.tokens.admits(over)).rejects.toThrow(TypeError);
		});

		it("reads a grant's actor once, so a getter answering otherwise the second time changes nothing", async () => {
			const place = await open({ revocable: true });
			const shifting = (first: Actor | undefined) => {
				let reads = 0;
				const given = Object.defineProperty({ ...grant }, "actor", {
					enumerable: true,
					get: () => (++reads === 1 ? first : chain(17)),
				});
				return { request: { grant: given as AccessGrant, grantType: "test" }, reads: () => reads };
			};
			const none = shifting(undefined);
			const issued = await place.tokens.issue(none.request);
			if (issued.kind !== "issued") throw new Error(issued.policy);
			expect(none.reads()).toBe(1);
			const checked = await place.tokens.verifyAccess(issued.access.token);
			if (checked.kind !== "valid") throw new Error(checked.reason);
			expect("actor" in checked.grant).toBe(false);
			const admitted = shifting(undefined);
			expect((await place.tokens.admits(admitted.request)).kind).toBe("allowed");
			expect(admitted.reads()).toBe(1);
			const deep = shifting(chain(17));
			await expect(place.tokens.issue(deep.request)).rejects.toThrow(TypeError);
		});

		it("refuses an authentication time beyond its allowance ahead of the clock", async () => {
			const place = await open({ revocable: true });
			const at = (authenticatedAt: number) => ({
				grant: { ...grant, authenticatedAt },
				grantType: "authorization_code",
			});
			expect(await place.tokens.issue(at(place.now() + authenticatedAheadMs + 1))).toMatchObject({
				kind: "refused",
				policy: "tokens",
				reason: "authenticated_ahead",
			});
			expect((await place.tokens.issue(at(place.now() + authenticatedAheadMs))).kind).toBe(
				"issued",
			);
		});

		it("throws unavailable where a policy cannot tell, never issuing", async () => {
			const place = await open({
				revocable: true,
				policies: [
					{
						name: "down",
						judge: async () => {
							throw new Unavailable("policy");
						},
					},
				],
			});
			await expect(
				place.tokens.issue({ grant, grantType: "client_credentials" }),
			).rejects.toSatisfy(isUnavailable);
		});

		it("never issues where a policy throws at once, and takes an answer other than allowed as a refusal", async () => {
			const throwing = await open({
				revocable: true,
				policies: [
					{
						name: "throws",
						judge: () => {
							throw new TypeError("a policy's fault");
						},
					},
				],
			});
			await expect(
				throwing.tokens.issue({ grant, grantType: "client_credentials" }),
			).rejects.toBeInstanceOf(TypeError);
			const odd = { kind: "denied" } as unknown as IssuanceVerdict;
			const unreadable = await open({
				revocable: true,
				policies: [{ name: "odd", judge: async () => odd }],
			});
			expect(
				await unreadable.tokens.issue({ grant, grantType: "client_credentials" }),
			).toMatchObject({ kind: "refused", policy: "odd" });
		});

		it("refuses a grant whose acr is empty or whose authentication time is no number, as the caller's mistake", async () => {
			const place = await open({ revocable: true });
			for (const malformed of [{ acr: "" }, { authenticatedAt: Number.NaN }]) {
				await expect(
					issueFor(place.tokens, { ...grant, ...malformed }),
					JSON.stringify(malformed),
				).rejects.toBeInstanceOf(RangeError);
			}
		});

		it("issues for the lifetime the issuing side asks, two seconds to a day, and refuses any other as its mistake", async () => {
			const place = await open({ revocable: true });
			const longer = await issueFor(place.tokens, grant, { lifetimeSeconds: 86_400 });
			expect(longer.expiresIn).toBe(86_400);
			expect((await issueFor(place.tokens, grant, { lifetimeSeconds: 2 })).expiresIn).toBe(2);
			const capped = await issueFor(place.tokens, grant, {
				lifetimeSeconds: 86_400,
				notAfter: place.now() + 120_000,
			});
			expect(capped.expiresIn).toBe(120);
			for (const lifetimeSeconds of [0, 1, 86_401, 1.5, Number.NaN]) {
				await expect(
					issueFor(place.tokens, grant, { lifetimeSeconds }),
					String(lifetimeSeconds),
				).rejects.toBeInstanceOf(RangeError);
			}
		});

		it("tells the access-token lifetime it applies where a grant gives none", async () => {
			const place = await open({ revocable: true });
			expect(place.tokens.accessTokenLifetimeSeconds()).toBe(defaultLifetimeSeconds);
			const set = await open({ revocable: true, lifetimeSeconds: 600 });
			expect(set.tokens.accessTokenLifetimeSeconds()).toBe(600);
			expect((await issueFor(set.tokens, grant)).expiresIn).toBe(600);
			expect(set.tokens.accessTokenLifetimeSeconds()).toBe(600);
		});

		it("caps a token's expiry at what it was issued for", async () => {
			const place = await open({ revocable: true });
			const issued = await issueFor(place.tokens, grant, { notAfter: place.now() + 120_000 });
			expect(issued.expiresAt).toBeLessThanOrEqual(place.now() + 120_000);
			expect(issued.expiresIn).toBe(120);
		});

		it("refuses, as its own rule, a token its cap leaves less than a second, and issues one a second", async () => {
			const place = await open({ revocable: true });
			for (const ahead of [-10_000, 0, 999]) {
				expect(
					await place.tokens.issue({ grant, grantType: "test" }, { notAfter: place.now() + ahead }),
					String(ahead),
				).toEqual({
					kind: "refused",
					policy: "tokens",
					reason: "no_lifetime_left",
					description: "expired",
				});
			}
			const issued = await issueFor(place.tokens, grant, { notAfter: place.now() + 1000 });
			expect(issued.expiresIn).toBe(1);
		});

		it("revokes a token, and only that one, directly or by its reference", async () => {
			const place = await open({ revocable: true });
			expect(place.tokens.revocable()).toBe(true);
			const [first, second, third] = [
				await issueFor(place.tokens, grant),
				await issueFor(place.tokens, grant),
				await issueFor(place.tokens, grant),
			];
			expect(await place.tokens.revokeAccess(first.token)).toEqual({ kind: "revoked" });
			expect(await place.tokens.revokeReferenced(referenceOf(second))).toEqual({ kind: "revoked" });
			for (const revoked of [first, second]) {
				expect(await place.tokens.verifyAccess(revoked.token)).toEqual({
					kind: "invalid",
					reason: "revoked",
				});
			}
			expect((await place.tokens.verifyAccess(third.token)).kind).toBe("valid");
			expect(await place.tokens.revokeAccess("not a token")).toEqual({ kind: "invalid" });
			expect(await place.tokens.revokeReferenced("not a reference")).toEqual({ kind: "invalid" });
		});

		it("tells who a token was issued to, revoked or not", async () => {
			const place = await open({ revocable: true });
			const issued = await issueFor(place.tokens, grant);
			await place.tokens.revokeAccess(issued.token);
			expect(await place.tokens.issuedToOf(issued.token)).toEqual({
				kind: "issued",
				issuedTo: "c",
			});
			expect(await place.tokens.issuedToOf("not a token")).toEqual({ kind: "invalid" });
		});

		it("answers unsupported to a revocation where revocation is not configured", async () => {
			const place = await open({ revocable: false });
			expect(place.tokens.revocable()).toBe(false);
			const issued = await issueFor(place.tokens, grant);
			expect(await place.tokens.revokeAccess(issued.token)).toEqual({ kind: "unsupported" });
			expect(await place.tokens.revokeReferenced(referenceOf(issued))).toEqual({
				kind: "unsupported",
			});
			expect((await place.tokens.verifyAccess(issued.token)).kind).toBe("valid");
		});

		it("stamps a binding of a known kind, and answers its token type and binding", async () => {
			const place = await open({ revocable: true });
			const binding = { ...place.known, confirmation: "thumb" };
			const issued = await issueFor(place.tokens, grant, { binding });
			expect(issued.tokenType).toBe(place.known.tokenType);
			expect(await place.tokens.verifyAccess(issued.token)).toMatchObject({
				kind: "valid",
				tokenType: place.known.tokenType,
				binding,
			});
		});

		it("fails a token bound by a member no kind of the composition writes", async () => {
			const place = await open({ revocable: true });
			const binding = { member: "unknown", confirmation: "thumb", tokenType: "UNKNOWN" };
			const issued = await issueFor(place.tokens, grant, { binding });
			expect(await place.tokens.verifyAccess(issued.token)).toEqual({
				kind: "invalid",
				reason: "shape",
			});
		});

		it("fails a token whose subject was revoked after it was issued", async () => {
			const place = await open({ revocable: true });
			const issued = await issueFor(place.tokens, grant);
			const other = await issueFor(place.tokens, { ...grant, subject: "t" });
			place.revokeSubject("s");
			expect(await place.tokens.verifyAccess(issued.token)).toEqual({
				kind: "invalid",
				reason: "revoked",
			});
			expect((await place.tokens.verifyAccess(other.token)).kind).toBe("valid");
		});
	});
}

/**
 * A stand-in for tests of the modules that use tokens: it keeps what it issued in memory, with
 * opaque tokens and no signing. Lifetimes run on the composition's clock and end as tokens' do,
 * with the same allowance past expiry for revocation and issued-to. It applies the contributed
 * access conditions and subject checks. A bound token verifies with its kind's token type, and
 * fails as shape when no binding kind of the composition writes its member, as tokens' does.
 */
export function tokensStandIn(
	options: { readonly revocable?: boolean; readonly lifetimeSeconds?: number } = {},
) {
	return defineModule(
		{
			name: "tokens",
			replicaSafe: false,
			takes: [accessConditions, subjectChecks, senderBindings, issuancePolicies],
		},
		(m) => [
			m.provide(tokens).by(async (c) => {
				const revocable = options.revocable ?? true;
				const configured = options.lifetimeSeconds ?? defaultLifetimeSeconds;
				const conditions = [
					...(await c.collect(accessConditions)),
					...(await c.collect(subjectChecks)),
				];
				type Kept = {
					grant: AccessGrant;
					id: string;
					issuedAt: number;
					expiresAt: number;
					binding?: Binding;
				};
				// The token type of each binding kind of the composition, by its `cnf` member, as tokens reads it.
				const kinds = new Map(
					(await c.collect(senderBindings)).map((kind) => [kind.member, kind.tokenType]),
				);
				const issued = new Map<string, Kept>();
				// tokens' own denylist, over a store in memory.
				const revoked = new Set<string>();
				const denylist = denylistOver(
					revocable
						? {
								save: async (id) => {
									const kept = revoked.has(id);
									revoked.add(id);
									return kept ? "exists" : "created";
								},
								holds: async (id) => revoked.has(id),
							}
						: undefined,
					c.clock,
				);
				const live = (token: string, allowanceMs = 0) => {
					const kept = issued.get(token);
					return kept && kept.expiresAt + allowanceMs > c.clock.now() ? kept : undefined;
				};
				const verify = async (token: string): Promise<AccessCheck> => {
					if (!issued.has(token)) return { kind: "invalid", reason: "shape" };
					const kept = live(token);
					if (!kept) return { kind: "invalid", reason: "expired" };
					if (await denylist.holds(kept.id)) return { kind: "invalid", reason: "revoked" };
					const issuedFor = { id: kept.id, subject: kept.grant.subject, issuedAt: kept.issuedAt };
					for (const condition of conditions) {
						if ((await condition.holds(issuedFor)) === "revoked")
							return { kind: "invalid", reason: "revoked" };
					}
					const tokenType = kept.binding ? kinds.get(kept.binding.member) : "Bearer";
					if (tokenType === undefined) return { kind: "invalid", reason: "shape" };
					return {
						kind: "valid",
						id: kept.id,
						grant: kept.grant,
						expiresAt: kept.expiresAt,
						tokenType,
						...(kept.binding ? { binding: { ...kept.binding, tokenType } } : {}),
					};
				};
				const judge = judging(await c.collect(issuancePolicies), c.clock.now);
				const issueAccess: IssueAccess = async (grant, limits) => {
					const lifetime = lifetimeOf(limits?.lifetimeSeconds, configured);
					const { iat, exp } = expiryOf(c.clock.now(), lifetime, limits?.notAfter);
					const id = tokenId(c.random);
					const token = `stand-in.${id}`;
					const binding = limits?.binding;
					return {
						access: {
							token,
							id,
							expiresAt: exp * 1000,
							expiresIn: exp - iat,
							tokenType: binding?.tokenType ?? "Bearer",
							...(grant.claims
								? { addedClaims: Object.freeze(Object.keys(grant.claims).sort()) }
								: {}),
						},
						// Kept only once handed out, so a token refused leaves nothing.
						keep: () => {
							issued.set(token, {
								grant: keptGrant(grant, iat),
								id,
								issuedAt: iat * 1000,
								expiresAt: exp * 1000,
								...(binding ? { binding: Object.freeze({ ...binding }) } : {}),
							});
						},
					};
				};
				const stand: Tokens = {
					revocable: () => denylist.revocable,
					accessTokenLifetimeSeconds: () => configured,
					...issuing(judge, issueAccess, c.clock.now),
					verifyAccess: verify,
					issuedToOf: async (token) => {
						const kept = live(token, denylistAllowanceMs);
						return kept ? { kind: "issued", issuedTo: kept.grant.issuedTo } : { kind: "invalid" };
					},
					revokeAccess: async (token) => {
						if (!denylist.revocable) return { kind: "unsupported" };
						const kept = live(token, denylistAllowanceMs);
						return kept ? denylist.revoke(kept.id, kept.expiresAt) : { kind: "invalid" };
					},
					revokeReferenced: async (reference) => {
						const referenced = namedBy(reference);
						return referenced
							? denylist.revoke(referenced.id, referenced.expiresAt)
							: { kind: "invalid" };
					},
				};
				return stand;
			}),
		],
	);
}
