import { auditStandIn } from "@mod/audit/testing";
import { claimsSelections, type Selection, selectionRecords } from "@mod/claims-selection";
import claimsSelectionModule from "@mod/claims-selection/module";
import claimsSelectionStore from "@mod/claims-selection-store/module";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import { type Addition, additions, type RedemptionHook, redemptionHooks } from "@mod/code-grant";
import { type Eraser, erasers, type Walk } from "@mod/erasure-extensions";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import httpServer from "@mod/http-server/module";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, contract, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import refreshModule from "@mod/refresh/module";
import { refreshConfig } from "@mod/refresh/testing";
import secretHashModule from "@mod/secret-hash/module";
import { sessions } from "@mod/session";
import { openedOf, sessionStandIn } from "@mod/session/testing";
import sessionParticipants from "@mod/session-participants/module";
import { type Space, store, storeControl } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import tokenControl from "@mod/token-control/module";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import { tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime();
const seen = contract<{
	readonly additions: readonly Addition[];
	readonly pins: readonly RedemptionHook[];
	readonly erasers: readonly Eraser[];
}>("through-seen");
const reader = defineModule(
	{ name: "reader", replicaSafe: true, takes: [additions, redemptionHooks, erasers] },
	(m) => [
		m.provide(seen).by(async (c) => ({
			additions: await c.collect(additions),
			pins: await c.collect(redemptionHooks),
			erasers: await c.collect(erasers),
		})),
	],
);
const allowed = allowancesFor({
	grants: ["authorization_code", "refresh_token"],
	scopes: ["read"],
	audiences: ["https://api"],
});
const target = { names: [], constraints: [{ name: "email", value: "a@example.com" }] };
const asked: Selection = { idToken: target, userinfo: target };
const signal = new AbortController().signal;

/** The real refresh and claims-selection over both wirings, on `storeModule`. */
const composed = (storeModule: Module) =>
	assemble({
		modules: [
			http,
			httpServer,
			tokensStandIn(),
			issuerModule,
			clientsModule,
			secretHashModule,
			grantCaller,
			clientAllowanceModule,
			tokenControl,
			rateLimitStandIn,
			auditStandIn().module,
			sessionStandIn,
			sessionParticipants,
			subjectRevocationStandIn,
			storeModule,
			refreshModule,
			wiring,
			claimsSelectionModule,
			claimsSelectionStore,
			reader,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			...issuerConfig({ url: "https://as.example" }),
			...clientsConfig([confidentialClient({ id: "app", sections: allowed })]),
			...refreshConfig(),
		},
		runtime,
	});

/** In `reader`, families started for alice; then an instance started after the window marks records indexed. */
async function boot() {
	const simulated = simulatedStore();
	const app = await composed(simulated.module);
	const { session } = openedOf(
		await app.get(sessions).open(testRequest(), {
			subject: "alice",
			amr: ["pwd"],
			authenticatedAt: runtime.clock.now(),
			provenSince: runtime.clock.now(),
		}),
	);
	const grant = { subject: "alice", issuedTo: "app", audience: ["https://api"], scope: ["read"] };
	/** A family started from a redemption, its code's selection kept first where `selection` is; its id. */
	const start = async (selection?: Selection) => {
		const issued = await app.get(tokens).issue({ grant, grantType: "authorization_code" });
		if (issued.kind !== "issued") throw new Error(issued.reason);
		const { token: _, ...access } = issued.access;
		const redemption = `r-${Math.random()}`;
		if (selection) {
			await app.get(claimsSelections).keepForCode(redemption, selection, 600_000, "alice");
		}
		for (const hook of app.get(seen).pins) await hook.pin(redemption, "alice");
		const refresh = app.get(seen).additions.find((a) => a.field === "refresh_token");
		const token = (await refresh?.issue({
			redemption,
			client: {
				id: "app",
				kind: "confidential",
				method: "client_secret_post",
				registered: true,
				section: <T>() => ({ grants: ["refresh_token"] }) as T,
			},
			subject: "alice",
			scope: ["read"],
			audience: ["https://api"],
			session: session.id,
			authenticatedAt: Date.now(),
			amr: ["pwd"],
			access,
		})) as string;
		return { token, id: token.split(".")[0] as string };
	};
	const refresh = (token: string) =>
		app
			.get(grantCalls)
			.call("refresh_token", "app", { grant_type: "refresh_token", refresh_token: token });
	/** Written raw, as a 0.19 instance kept it: format 1, no subject. */
	const legacy = (name: string, value: object) =>
		app.get(selectionRecords).create(name, value as never, 3_600_000, "alice");
	const indexed = async () => {
		simulated.mark("subject-records.phase", "indexed");
		const inner = app.get(store);
		const shared = defineModule({ name: "store", replicaSafe: true, takes: [] }, (m) => [
			m.provide(store).by(() => inner),
			m.provide(storeControl).by(() => app.get(storeControl)),
		]);
		const after = await composed(shared);
		const eraser = after.get(seen).erasers.find((e) => e.name === "claims-selection");
		if (!eraser) throw new Error("no eraser claims-selection");
		const walk: Walk = {
			sweep: async (space, cursor) => {
				const page = await inner.scan({ name: space, guarantees: [] } as Space, cursor);
				return page.cursor === undefined
					? { keys: page.keys, server: "one" }
					: { keys: page.keys, cursor: page.cursor, server: "one" };
			},
		};
		return { after, eraser, walk };
	};
	return { app, start, refresh, legacy, indexed };
}

it("migrates selections written raw by reading each family's subject through refresh, then erases them with the subject", async () => {
	const { start, refresh, legacy, indexed } = await boot();
	// Format 2, written raw in `reader`: the code's selection, the pin and the family's target.
	const kept = await start(asked);
	// 0.19's family targets: a live family's, a revoked family's, and one whose family was never founded.
	const live = await start();
	const revoked = await start();
	await refresh(revoked.token);
	expect(await refresh(revoked.token)).toMatchObject({ kind: "error", error: "invalid_grant" });
	for (const id of [live.id, revoked.id, "never-founded"]) {
		expect(await legacy(`f.${id}`, { format: 1, target })).toBe("created");
	}

	const { after, eraser, walk } = await indexed();
	expect(eraser.erasable).toBe(true);
	const [report] = await eraser.migrate(walk, signal);
	expect(report).toMatchObject({
		kind: "migrated",
		space: "claims-selection-store.selections",
		removed: 2,
	});
	const records = after.get(selectionRecords);
	expect(await records.read(`f.${kept.id}`)).toMatchObject({ format: 2, subject: "alice" });
	expect(await records.read(`f.${live.id}`)).toEqual({ format: 1, target });
	expect(await records.read(`f.${revoked.id}`)).toBeUndefined();
	expect(await records.read("f.never-founded")).toBeUndefined();

	expect((await eraser.online("alice", signal)).reports.map((r) => r.kind)).toEqual(["erased"]);
	expect(await records.read(`f.${kept.id}`)).toBeUndefined();
	expect(await records.read(`f.${live.id}`)).toBeUndefined();
});

it("stops the migration on a token's target 0.19 kept, giving the one bound to run again after", async () => {
	const { legacy, indexed } = await boot();
	expect(await legacy("t.tok-0.19", { format: 1, target })).toBe("created");
	const { eraser, walk } = await indexed();
	const [report] = await eraser.migrate(walk, signal);
	expect(report).toMatchObject({
		kind: "stopped",
		reason: expect.stringContaining("86,520 s after the last 0.19 instance stopped"),
	});
});
