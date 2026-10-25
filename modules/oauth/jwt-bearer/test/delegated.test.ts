import { createHash } from "node:crypto";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import { clientSources } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient, publicClient } from "@mod/clients/testing";
import externalJwtModule from "@mod/external-jwt/module";
import { type GrantInput, type GrantOutcome, targetRules } from "@mod/grants";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import {
	assemble,
	BootRefused,
	defineModule,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import outboundModule from "@mod/outbound/module";
import { memoryRecords } from "@mod/records/testing";
import secretHashModule from "@mod/secret-hash/module";
import { simulatedStore } from "@mod/store/testing";
import { revocations } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import { issuancePolicies, tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { decodeJwt } from "jose";
import { describe, expect, it, vi } from "vitest";
import {
	type DelegatedAssertions,
	delegatedAssertions,
	linkedSubjects,
	signerKeys,
	spentAssertions,
} from "../src/contract.ts";
import jwtBearer from "../src/module.ts";

/** Each assertion the grant's own checking was asked of, so a test can tell no delegated one reaches it. */
const ordinary = vi.hoisted(() => ({ asked: [] as string[] }));
vi.mock("../src/assertion/assertion.ts", async (original) => {
	const real = await original<typeof import("../src/assertion/assertion.ts")>();
	return {
		...real,
		check: (
			assertion: string,
			...rest: Parameters<typeof real.check> extends [string, ...infer R] ? R : never
		) => {
			ordinary.asked.push(assertion);
			return real.check(assertion, ...rest);
		},
	};
});

const now = 1_800_000_000_000;
const issuer = "https://as.example";
const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/** An issuer whose assertions another module checks: their audience is an app, never this server. */
const idp = "https://idp.example";
const jkt = "thumbprint-of-the-device-key";
const digest = createHash("sha256").update(jkt, "ascii").digest("base64url");
type Binding = NonNullable<GrantInput["binding"]>;
const proved: Binding = { member: "jkt", confirmation: jkt, tokenType: "DPoP" };

const valid = {
	kind: "valid",
	subject: "acct-1",
	issuedAt: now - 10_000,
	expiresAt: now + 600_000,
	clients: ["app"],
};
/** An assertion shaped as a JWT, never signed: the delegate reads the answer it is to give from it. */
const sent = (answer: unknown = valid, iss: unknown = idp) => {
	const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
	return `${part({ alg: "RS256" })}.${part({ iss, n: Math.random(), answer })}.signature`;
};

/** A delegate that answers each assertion as it says, and spends each once, unless scripted otherwise. */
function delegating(
	script: {
		readonly name?: string;
		readonly issuers?: readonly string[];
		readonly check?: (assertion: string) => Promise<unknown>;
		readonly spend?: (assertion: string) => Promise<unknown>;
	} = {},
) {
	const spent: string[] = [];
	const name = script.name ?? "delegate";
	const module = defineModule({ name, takes: [] }, (m) => [
		m.contribute(delegatedAssertions).by(
			() =>
				({
					declaredBy: name,
					issuers: script.issuers ?? [idp],
					check: (a: string) =>
						script.check ? script.check(a) : Promise.resolve(decodeJwt(a).answer),
					spend: async (a: string) => {
						const told = script.spend
							? await script.spend(a)
							: spent.includes(a)
								? "replayed"
								: "spent";
						spent.push(a);
						return told;
					},
				}) as unknown as DelegatedAssertions,
		),
	]);
	return { module, spent };
}

const allowed = allowancesFor({
	grants: [grantType],
	scopes: ["read"],
	"default-scopes": ["read"],
});
/** Each name the grant's own store was asked to keep, which a delegated assertion never reaches. */
const stored: string[] = [];
const spentStore = defineModule({ name: "spent-assertions", takes: [] }, (m) => [
	m.provide(spentAssertions).by(() => {
		const stand = memoryRecords<true>(() => now, { shards: 1, perShard: 1 });
		return {
			save: (name: string, lifetimeMs: number) => {
				stored.push(name);
				return stand.records.create(name, true, lifetimeMs);
			},
		};
	}),
]);

function assembly(
	extra: readonly Module[],
	section: Record<string, unknown> = { "delegated-issuers": [idp] },
	log = quietRuntime().log,
) {
	const location = defineModule({ name: "token-endpoint-location", takes: [] }, (m) => [
		m.provide(tokenEndpointLocation).by(() => ({ url: `${issuer}/oauth/token` })),
	]);
	return {
		modules: [
			location,
			http,
			tokensStandIn(),
			issuerModule,
			clientsModule,
			secretHashModule,
			grantCaller,
			clientAllowanceModule,
			outboundModule,
			externalJwtModule,
			simulatedStore().module,
			subjectRevocationStandIn,
			jwtBearer,
			spentStore,
			...extra,
		],
		config: {
			...kernelConfig(),
			...httpConfig(),
			...issuerConfig({ url: issuer }),
			...clientsConfig([
				confidentialClient({ id: "app", sections: allowed }),
				confidentialClient({ id: "other", sections: allowed }),
				publicClient({ id: "phone", sections: allowed }),
				publicClient({
					id: "old-phone",
					sections: { ...allowed, "jwt-bearer": { "accept-unbound": true } },
				}),
			]),
			"jwt-bearer": { issuers: [], ...section },
		},
		runtime: quietRuntime({ clock: { now: () => now }, log }),
	};
}

async function serve(
	extra: readonly Module[],
	log = quietRuntime().log,
	section?: Record<string, unknown>,
) {
	const app = await assemble(assembly(extra, section, log));
	const grant = (client: string, a: string, binding?: Binding, more: Record<string, string> = {}) =>
		app
			.get(grantCalls)
			.call(
				grantType,
				client,
				{ grant_type: grantType, assertion: a, ...more },
				binding ? { binding } : {},
			);
	return { app, grant };
}
const saidOf = (outcome: GrantOutcome) =>
	outcome.kind === "error" ? `${outcome.error}: ${outcome.description}` : "issued";
const refusalsOf = (extra: readonly Module[], section: Record<string, unknown>) =>
	assemble(assembly(extra, section)).then(
		() => [],
		(error: unknown) => (error instanceof BootRefused ? error.refusals : Promise.reject(error)),
	);

describe("delegated issuers", () => {
	it("issues for an assertion the delegate takes, whose audience is no server's of ours, to the one client it is for", async () => {
		const d = delegating();
		const s = await serve([d.module]);
		const a = sent();
		const outcome = await s.grant("app", a);
		if (outcome.kind !== "issued") throw new Error(saidOf(outcome));
		const checked = await s.app.get(tokens).verifyAccess(String(outcome.body.access_token));
		expect(checked).toMatchObject({ kind: "valid", grant: { subject: "acct-1", issuedTo: "app" } });
		if (checked.kind === "valid") expect(checked.expiresAt).toBeLessThanOrEqual(valid.expiresAt);
		expect(d.spent).toEqual([a]);
		// Once only, by the delegate's record; the grant's own store is never asked.
		expect(saidOf(await s.grant("app", a))).toBe("invalid_grant: assertion replayed");
		expect(stored).toEqual([]);
	});

	it("answers the delegate's refusal as an unknown signer, spends nothing, and tries no other way", async () => {
		const d = delegating();
		const s = await serve([d.module]);
		expect(saidOf(await s.grant("app", sent({ kind: "invalid" })))).toBe(
			"invalid_grant: untrusted signer",
		);
		expect(saidOf(await s.grant("app", sent(valid, "https://nobody.example")))).toBe(
			"invalid_grant: untrusted signer",
		);
		expect(d.spent).toEqual([]);
		expect(stored).toEqual([]);
	});

	it("refuses an assertion for another client, leaving it usable", async () => {
		const d = delegating();
		const s = await serve([d.module]);
		const a = sent();
		expect(saidOf(await s.grant("other", a))).toBe(
			"invalid_grant: assertion is for another client",
		);
		expect(d.spent).toEqual([]);
		expect(saidOf(await s.grant("app", a))).toBe("issued");
	});

	it("refuses an assertion with less than a second left before its delegate spends it, as the exchange does", async () => {
		const d = delegating();
		const s = await serve([d.module]);
		// The delegate took it within its clock allowance, past or at its end.
		for (const left of [-5_000, 0, 999]) {
			expect(
				saidOf(await s.grant("app", sent({ ...valid, expiresAt: now + left }))),
				String(left),
			).toBe("invalid_grant: expired");
		}
		expect(d.spent).toEqual([]);
		expect(saidOf(await s.grant("app", sent({ ...valid, expiresAt: now + 1000 })))).toBe("issued");
	});

	it("gives no token for an assertion made before its subject's revocation", async () => {
		const d = delegating();
		const s = await serve([d.module]);
		await s.app.get(revocations).record("acct-1", { keepDelegations: false });
		const a = sent({ ...valid, issuedAt: now - 120_000 });
		expect(saidOf(await s.grant("app", a))).toBe("invalid_grant: assertion revoked");
		expect(d.spent).toEqual([]);
	});

	it("asks the client's allowance, the audience and the issuance policies before the delegate spends, leaving the assertion usable", async () => {
		const refusingAudience = defineModule({ name: "refusing-audience", takes: [] }, (m) => [
			m.contribute(targetRules).by(() => ({
				target: ({ param, audience }) =>
					param("resource")
						? { kind: "error", error: "invalid_target", description: "not here" }
						: { kind: "audience", audience },
			})),
		]);
		let refusing = true;
		const policy = defineModule({ name: "refusing-policy", takes: [] }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "test-policy",
				judge: async () =>
					refusing
						? { kind: "refused", reason: "test_reason", description: "refused here" }
						: { kind: "allowed" },
			})),
		]);
		const d = delegating();
		const s = await serve([d.module, refusingAudience, policy]);
		const a = sent();
		expect(saidOf(await s.grant("app", a, undefined, { scope: "write" }))).toMatch(
			/^invalid_scope/,
		);
		expect(saidOf(await s.grant("app", a, undefined, { resource: "https://api.example" }))).toBe(
			"invalid_target: not here",
		);
		expect(saidOf(await s.grant("app", a))).toBe("invalid_grant: refused here");
		expect(d.spent).toEqual([]);
		refusing = false;
		expect(saidOf(await s.grant("app", a))).toBe("issued");
	});

	it("tries no other way for a delegated issuer's assertion: no trusted issuer's keys, subjects or store are asked", async () => {
		const asked: string[] = [];
		const own = "https://own.example";
		const spies = defineModule({ name: "spies", takes: [] }, (m) => [
			m.contribute(signerKeys).by(() => ({
				issuer: own,
				keysOf: async () => {
					asked.push("keys");
					return { kind: "none" };
				},
			})),
			m.contribute(linkedSubjects).by(() => ({
				declaredBy: "spies",
				subjectOf: async () => {
					asked.push("subject");
					return { kind: "none" };
				},
			})),
		]);
		const d = delegating();
		const section = {
			issuers: [{ issuer: own, subject: "linked", upstream: "own" }],
			"delegated-issuers": [idp],
		};
		const s = await serve([d.module, spies], undefined, section);
		ordinary.asked.length = 0;
		for (const answer of [{ kind: "invalid" }, valid]) {
			await s.grant("app", sent(answer));
		}
		expect(ordinary.asked).toEqual([]);
		expect(asked).toEqual([]);
		expect(stored).toEqual([]);
		expect(d.spent).toHaveLength(1);
		// The ordinary checking is what an assertion of any other issuer reaches: the spy sees it.
		const ownAssertion = sent(valid, own);
		expect(saidOf(await s.grant("app", ownAssertion))).toBe("invalid_grant: untrusted signer");
		expect(ordinary.asked).toEqual([ownAssertion]);
	});

	describe("a public client", () => {
		const forPhones = { ...valid, clients: ["phone", "old-phone"] };
		const bound = { ...forPhones, holderDigest: digest };
		const refusedKey = "invalid_grant: the request does not prove the key the assertion names";

		it("proves the key the assertion's digest names, by DPoP", async () => {
			const s = await serve([delegating().module]);
			expect(saidOf(await s.grant("phone", sent(bound), proved))).toBe("issued");
			const other = { ...proved, confirmation: "another-key" };
			expect(saidOf(await s.grant("phone", sent(bound), other))).toBe(refusedKey);
			expect(saidOf(await s.grant("phone", sent(bound)))).toBe(refusedKey);
			expect(saidOf(await s.grant("phone", sent(forPhones)))).toBe(refusedKey);
		});

		it("with accept-unbound, takes one with no digest without a key, and still proves a digest's key", async () => {
			const logged = recordingLog();
			const d = delegating();
			const s = await serve([d.module], logged.log);
			expect(logged.lines().filter((e) => e.event === "jwt-bearer.accept_unbound")).toEqual([
				expect.objectContaining({ level: "warn", fields: { client: "old-phone" } }),
			]);
			expect(saidOf(await s.grant("old-phone", sent(forPhones)))).toBe("issued");
			expect(logged.lines().filter((e) => e.event === "jwt-bearer.accept_unbound").length).toBe(2);
			// A digest signed into the assertion is always proved: sending no proof never skips it.
			const a = sent(bound);
			expect(saidOf(await s.grant("old-phone", a))).toBe(refusedKey);
			expect(saidOf(await s.grant("old-phone", a, { ...proved, confirmation: "x" }))).toBe(
				refusedKey,
			);
			expect(d.spent).toEqual([expect.any(String)]);
			expect(saidOf(await s.grant("old-phone", a, proved))).toBe("issued");
		});

		it("reads accept-unbound for registered clients alone: one a source names cannot give it to itself", async () => {
			const logged = recordingLog();
			const source = defineModule({ name: "a-source", takes: [] }, (m) => [
				m.contribute(clientSources).by(() => ({
					find: async (id: string) =>
						id === "named-phone"
							? {
									id,
									kind: "public" as const,
									method: "none",
									sections: { ...allowed, "jwt-bearer": { "accept-unbound": true } },
								}
							: undefined,
				})),
			]);
			const s = await serve([delegating().module, source], logged.log);
			const unbound = { ...valid, clients: ["named-phone"] };
			expect(saidOf(await s.grant("named-phone", sent(unbound)))).toBe(refusedKey);
			expect(logged.lines().filter((e) => e.fields.client === "named-phone")).toEqual([]);
		});

		it("leaves a confidential client's digest unread", async () => {
			const s = await serve([delegating().module]);
			expect(saidOf(await s.grant("app", sent({ ...valid, holderDigest: digest })))).toBe("issued");
		});
	});

	it("fails closed on an answer of no shape the contract gives, or an error that is not Unavailable", async () => {
		for (const answer of [
			{ kind: "valid" },
			{ ...valid, clients: [] },
			{ ...valid, subject: "" },
			{ ...valid, expiresAt: "soon" },
			{ ...valid, holderDigest: "short" },
			{ kind: "taken" },
			null,
		]) {
			const d = delegating();
			const s = await serve([d.module]);
			await expect(s.grant("app", sent(answer)), JSON.stringify(answer)).rejects.toBeInstanceOf(
				Unavailable,
			);
			expect(d.spent).toEqual([]);
		}
		const none = delegating({ check: async () => undefined });
		await expect((await serve([none.module])).grant("app", sent())).rejects.toBeInstanceOf(
			Unavailable,
		);
		const thrown = delegating({ check: () => Promise.reject(new TypeError("a bug")) });
		await expect((await serve([thrown.module])).grant("app", sent())).rejects.toBeInstanceOf(
			Unavailable,
		);
		for (const told of [undefined, "ok", { kind: "spent" }, "consumed"]) {
			const d = delegating({ spend: async () => told });
			const s = await serve([d.module]);
			await expect(s.grant("app", sent()), String(told)).rejects.toBeInstanceOf(Unavailable);
		}
		const broken = delegating({ spend: () => Promise.reject(new TypeError("a bug")) });
		await expect((await serve([broken.module])).grant("app", sent())).rejects.toBeInstanceOf(
			Unavailable,
		);
		const down = delegating({ spend: () => Promise.reject(new Unavailable("delegate")) });
		await expect((await serve([down.module])).grant("app", sent())).rejects.toBeInstanceOf(
			Unavailable,
		);
	});

	describe("at boot", () => {
		const at = (i: number) => `jwt-bearer.delegated-issuers.${i}`;
		it("refuses an issuer no module checks, or two do, or one named twice", async () => {
			expect(await refusalsOf([], { "delegated-issuers": [idp] })).toEqual([
				{ where: at(0), reason: "no module checks this issuer's assertions" },
			]);
			const two = [delegating({ name: "one" }).module, delegating({ name: "two" }).module];
			expect(await refusalsOf(two, { "delegated-issuers": [idp] })).toEqual([
				{ where: at(0), reason: "more than one module checks this issuer's assertions: one, two" },
			]);
			expect(await refusalsOf([delegating().module], { "delegated-issuers": [idp, idp] })).toEqual([
				{ where: at(1), reason: "names the same issuer as jwt-bearer.delegated-issuers.0" },
			]);
		});

		it("refuses a delegated issuer another way also reads, whatever the order", async () => {
			const own = { issuer: idp, subject: "as-is", "subject-is-key-thumbprint": true };
			const prefixed = {
				issuer: "https://devices.example",
				subject: "as-is",
				"subject-is-key-thumbprint": true,
				"self-issued-prefix": "https://idp.",
			};
			const signing = (iss: string) =>
				defineModule({ name: `keys-${new URL(iss).hostname}`, takes: [] }, (m) => [
					m
						.contribute(signerKeys)
						.by(() => ({ issuer: iss, keysOf: async () => ({ kind: "none" }) })),
				]);
			for (const issuers of [[own], [own, prefixed], [prefixed]]) {
				const refused = await refusalsOf(
					[delegating().module, ...issuers.map((i) => signing(i.issuer))],
					{ issuers, "delegated-issuers": [idp] },
				);
				expect(
					refused.filter((r) => r.where === at(0)),
					JSON.stringify(issuers),
				).toEqual(
					issuers.map((i, b) =>
						i === own
							? { where: at(0), reason: `is the issuer of jwt-bearer.issuers.${b}` }
							: {
									where: at(0),
									reason: `starts with the self-issued prefix of jwt-bearer.issuers.${b}`,
								},
					),
				);
			}
		});

		it("refuses assertions delegated for an issuer it does not name", async () => {
			expect(
				await refusalsOf(
					[delegating()].map((d) => d.module),
					{ "delegated-issuers": [] },
				),
			).toEqual([
				{
					where: "jwt-bearer.delegated-issuers",
					reason:
						"assertions are delegated for 1 issuer none of these names: name it here, or leave out the module that contributes them",
				},
			]);
		});

		it("boots with none delegated and no module delegating", async () => {
			expect(await refusalsOf([], {})).toEqual([]);
		});
	});
});
