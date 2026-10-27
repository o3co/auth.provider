import { createHash } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import {
	type ConstrainedFamilyList,
	claimsSelections,
	constrainedFamilyList,
	type Selection,
	type SelectionMode,
	type SelectionRecords,
	selectionConsents,
	selectionRecords,
} from "@mod/claims-selection";
import claimsSelectionModule from "@mod/claims-selection/module";
import { claimsSelectionConfig } from "@mod/claims-selection/testing";
import claimsSelectionStore from "@mod/claims-selection-store/module";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import { codes } from "@mod/code-grant";
import codeGrantModule from "@mod/code-grant/module";
import { codeGrantConfig } from "@mod/code-grant/testing";
import codeGrantStore from "@mod/code-grant-store/module";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, type Contract, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import refreshModule from "@mod/refresh/module";
import { refreshConfig } from "@mod/refresh/testing";
import refreshStore from "@mod/refresh-store/module";
import secretHashModule from "@mod/secret-hash/module";
import { sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import sessionParticipants from "@mod/session-participants/module";
import sessionRequirements from "@mod/session-requirements/module";
import sessionTokensModule from "@mod/session-tokens/module";
import { sessionTokensInMemory } from "@mod/session-tokens/testing";
import { type SimulatedStore, simulatedStore } from "@mod/store/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import tokenControl from "@mod/token-control/module";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import tokenExchange from "@mod/token-exchange/module";
import { tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { afterEach, describe, expect, it } from "vitest";
import { constrainedFamilyRevocation } from "../src/contract.ts";
import revocationModule from "../src/module.ts";

// The composition's clock, which a test moves on with the store's.
let shift = 0;
const runtime = quietRuntime({ clock: { now: () => Date.now() + shift } });
const stops: (() => Promise<void>)[] = [];
afterEach(async () => {
	shift = 0;
	for (const stop of stops.splice(0)) await stop().catch(() => undefined);
});
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const exchangeType = "urn:ietf:params:oauth:grant-type:token-exchange";
const consenting = defineModule({ name: "consenting", takes: [] }, (m) => [
	m.contribute(selectionConsents).by(() => ({ consented: async () => true })),
]);
const constrained: Selection = {
	idToken: { names: [], constraints: [] },
	userinfo: { names: [], constraints: [{ name: "email", value: "a@example.com" }] },
};

/** A point a run is held at until the test opens it, or never: `arrived` once the run reached it. */
function gate() {
	let open = () => {};
	let arrive = () => {};
	const opened = new Promise<void>((resolve) => {
		open = resolve;
	});
	const arrived = new Promise<void>((resolve) => {
		arrive = resolve;
	});
	return {
		arrived,
		open: () => open(),
		reached: async () => {
			arrive();
			await opened;
		},
	};
}

/** Where a test holds or breaks the selection store's calls, by the name or the family. */
type Hooks = {
	beforeSave?: ((name: string) => void | Promise<void>) | undefined;
	beforeAdd?: ((id: string) => void | Promise<void>) | undefined;
	afterAdd?: ((id: string) => void | Promise<void>) | undefined;
};

/** The same module, its provision of `provided` wrapped as built. */
function around<T extends object>(
	module: Module,
	provided: Contract<T>,
	wrap: (made: T) => T,
): Module {
	return {
		...module,
		provides: (module.provides ?? []).map((part) =>
			part.contract !== provided
				? part
				: {
						contract: part.contract,
						create: async (c: Parameters<typeof part.create>[0]) =>
							wrap((await part.create(c)) as T),
					},
		),
	};
}

/** claims-selection-store over the shared store, its records and list held where the hooks say. */
const heldStore = (hooks: Hooks) =>
	around<ConstrainedFamilyList>(
		around<SelectionRecords>(claimsSelectionStore, selectionRecords, (records) => ({
			read: records.read,
			save: async (name, value, ms) => {
				await hooks.beforeSave?.(name);
				return records.save(name, value, ms);
			},
		})),
		constrainedFamilyList,
		(list) => ({
			...list,
			add: async (id) => {
				await hooks.beforeAdd?.(id);
				await list.add(id);
				await hooks.afterAdd?.(id);
			},
		}),
	);

/** A host of the deployment over `store`, as an instance runs it: what it keeps, it keeps there. */
async function host(
	simulated: SimulatedStore,
	mode: SelectionMode,
	hooks: Hooks = {},
	sizes: Record<string, number> = {},
) {
	const app = await assemble({
		modules: [
			http,
			tokensStandIn({ revocable: true }),
			issuerModule,
			clientsModule,
			secretHashModule,
			grantCaller,
			clientAllowanceModule,
			tokenControl,
			rateLimitStandIn,
			auditStandIn().module,
			sessionStandIn,
			sessionRequirements,
			sessionParticipants,
			subjectRevocationStandIn,
			simulated.module,
			sessionTokensModule,
			sessionTokensInMemory().module,
			codeGrantModule,
			codeGrantStore,
			refreshModule,
			refreshStore,
			claimsSelectionModule,
			heldStore(hooks),
			consenting,
			tokenExchange,
			revocationModule,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			...issuerConfig({ url: "https://as.example" }),
			...clientsConfig([
				confidentialClient({
					id: "app",
					sections: allowancesFor({
						grants: ["authorization_code", "refresh_token", exchangeType],
						scopes: ["read"],
						audiences: ["https://api"],
					}),
				}),
			]),
			...codeGrantConfig(),
			...refreshConfig(),
			...claimsSelectionConfig({ mode }),
			"claims-selection-store": sizes,
		},
		runtime,
	});
	await app.start();
	stops.push(() => app.stop(1000));
	const kept = await keeper(app);
	const { session } = await app.get(sessions).complete(testRequest(), {
		subject: "alice",
		amr: ["pwd"],
		authenticatedAt: runtime.clock.now(),
	});
	const grant = async (grantType: string, form: Record<string, string>) => {
		const outcome = await app
			.get(grantCalls)
			.call(grantType, "app", { grant_type: grantType, ...form })
			.catch(() => ({ kind: "unavailable" as const }));
		if (outcome.kind === "issued") return { ...outcome.body } as Record<string, string>;
		return { error: outcome.kind === "unavailable" ? "temporarily_unavailable" : outcome.error };
	};
	/** A code for alice, kept with `selection` by a host still on where given, redeemed here. */
	const redeem = async (selection?: Selection) => {
		const code = await app.get(codes).issue({
			clientId: "app",
			redirectUri: "https://app.example/cb",
			challenge,
			scope: ["read"],
			audience: ["https://api"],
			session: session.id,
			subject: "alice",
		});
		if (selection) await kept(app.get(codes).redemptionOf(code), selection);
		return grant("authorization_code", {
			code,
			redirect_uri: "https://app.example/cb",
			code_verifier: verifier,
		});
	};
	const refresh = (token: string | undefined) =>
		grant("refresh_token", { refresh_token: token ?? "" });
	const active = async (token: string | undefined) =>
		(await app.get(tokens).verifyAccess(token ?? "")).kind === "valid";
	const run = () => app.get(constrainedFamilyRevocation).run();
	return { app, redeem, refresh, grant, active, run };
}

/** A host still on, over the same store as `app`, keeping a code's selection there as such a host does. */
async function keeper(app: { get<T>(contract: Contract<T>): T }) {
	const sharing = defineModule({ name: "shared-selections", takes: [] }, (m) => [
		m.provide(selectionRecords).by(() => app.get(selectionRecords)),
		m.provide(constrainedFamilyList).by(() => app.get(constrainedFamilyList)),
	]);
	const on = await assemble({
		modules: [claimsSelectionModule, sharing, consenting],
		config: { ...kernelConfig(), ...claimsSelectionConfig({ mode: "on" }) },
		runtime,
	});
	return (redemption: string, selection: Selection) =>
		on.get(claimsSelections).keepForCode(redemption, selection, 600_000);
}

/** Whether a refresh token, where one was given, still refreshes. */
const refreshes = async (h: Awaited<ReturnType<typeof host>>, token: string | undefined) =>
	token !== undefined && (await h.refresh(token)).access_token !== undefined;

describe("revoking the constrained families, at each point a run can stop or meet another", () => {
	it("revokes what a refresh running beside the revocation issued, the refresh held after its rotation", async () => {
		const simulated = simulatedStore();
		const hooks: Hooks = {};
		const h = await host(simulated, "draining", hooks);
		const first = await h.redeem(constrained);
		const held = gate();
		hooks.beforeSave = (name) => (name.startsWith("t.") ? held.reached() : undefined);
		const refreshing = h.refresh(first.refresh_token);
		await held.arrived;
		hooks.beforeSave = undefined;
		expect(await h.run()).toMatchObject({ kind: "run", revoked: 1, failed: { revocations: 0 } });
		held.open();
		const refreshed = await refreshing;
		expect(await h.active(refreshed.access_token)).toBe(false);
		expect(await refreshes(h, refreshed.refresh_token)).toBe(false);
		expect(await refreshes(h, first.refresh_token)).toBe(false);
	});

	it("revokes the family of an exchange held past the code's lifetime, or gives none", async () => {
		const simulated = simulatedStore();
		const hooks: Hooks = {};
		const h = await host(simulated, "draining", hooks);
		const held = gate();
		hooks.beforeSave = (name) => (name.startsWith("p.") ? held.reached() : undefined);
		const exchanging = h.redeem(constrained);
		await held.arrived;
		hooks.beforeSave = undefined;
		// T2 passes while the exchange is held after its code was taken.
		shift += 11 * 60_000;
		simulated.shiftClock(11 * 60_000);
		held.open();
		const late = await exchanging;
		expect(await h.run()).toMatchObject({ kind: "run", failed: { revocations: 0, reads: 0 } });
		expect(await refreshes(h, late.refresh_token)).toBe(false);
		expect(await h.active(late.access_token)).toBe(false);
	});

	// A host stopping is its run left held for good; the store restarts, keeping only what it holds
	// durably, and the composition reads it again as an instance started anew would.
	it("leaves no family, and nothing to revoke, where a host stops between keeping a family's selection and listing it", async () => {
		const simulated = simulatedStore();
		const stopped = gate();
		const hooks: Hooks = { beforeAdd: () => stopped.reached() };
		const h = await host(simulated, "draining", hooks);
		void h.redeem(constrained);
		await stopped.arrived;
		hooks.beforeAdd = undefined;
		await simulated.restart();
		expect(await h.run()).toMatchObject({ kind: "run", revoked: 0, expired: 0 });
	});

	it("revokes, once, a family listed by a host that stopped before it started the family", async () => {
		const simulated = simulatedStore();
		const stopped = gate();
		const hooks: Hooks = { afterAdd: () => stopped.reached() };
		const h = await host(simulated, "draining", hooks);
		void h.redeem(constrained);
		await stopped.arrived;
		hooks.afterAdd = undefined;
		await simulated.restart();
		expect(await h.run()).toMatchObject({ kind: "run", revoked: 1, failed: { revocations: 0 } });
		expect(await h.run()).toMatchObject({ kind: "run", revoked: 0 });
	});

	it("lists, and revokes, a family whose selection was written though its answer was lost", async () => {
		const simulated = simulatedStore();
		const h = await host(simulated, "draining", {
			beforeSave: (name) => {
				if (name.startsWith("f.")) simulated.loseNextReply();
			},
		});
		const first = await h.redeem(constrained);
		expect(await refreshes(h, first.refresh_token)).toBe(true);
		expect(await h.run()).toMatchObject({ kind: "run", revoked: 1, failed: { revocations: 0 } });
	});

	it("starts no constrained family past a full list, voiding its code, and leaves every other family as it was", async () => {
		const h = await host(
			simulatedStore(),
			"on",
			{},
			{ "constrained-shards": 1, "constrained-per-shard": 1 },
		);
		const kept = await h.redeem(constrained);
		const refused = await h.redeem(constrained);
		expect(refused).toEqual({ error: "temporarily_unavailable" });
		const plain = await h.redeem();
		expect(await refreshes(h, plain.refresh_token)).toBe(true);
		expect(await refreshes(h, kept.refresh_token)).toBe(true);
	});
});
