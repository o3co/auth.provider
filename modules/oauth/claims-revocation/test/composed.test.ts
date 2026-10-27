import { createHash } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import { claimsSelections, type Selection, selectionConsents } from "@mod/claims-selection";
import claimsSelectionModule from "@mod/claims-selection/module";
import { claimsSelectionConfig, claimsSelectionInMemory } from "@mod/claims-selection/testing";
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
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
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
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import tokenControl from "@mod/token-control/module";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import tokenExchange from "@mod/token-exchange/module";
import { tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { afterEach, expect, it } from "vitest";
import { constrainedFamilyRevocation } from "../src/contract.ts";
import revocationModule from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => Date.now() } });
const stops: (() => Promise<void>)[] = [];
afterEach(async () => {
	for (const stop of stops.splice(0)) await stop();
});
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const exchangeType = "urn:ietf:params:oauth:grant-type:token-exchange";
const allowed = (grants: string[]) =>
	allowancesFor({ grants, scopes: ["read"], audiences: ["https://api"] });
const consenting = defineModule({ name: "consenting", takes: [] }, (m) => [
	m.contribute(selectionConsents).by(() => ({ consented: async () => true })),
]);
const constrained: Selection = {
	idToken: { names: [], constraints: [] },
	userinfo: { names: [], constraints: [{ name: "email", value: "a@example.com" }] },
};

/** A host that is draining, its selections kept where a host still on keeps them too. */
async function draining() {
	const selections = claimsSelectionInMemory();
	const config = {
		...kernelConfig(),
		...httpConfig({ "public-origin": "https://as.example" }),
		...issuerConfig({ url: "https://as.example" }),
		...clientsConfig([
			confidentialClient({
				id: "app",
				sections: allowed(["authorization_code", "refresh_token", exchangeType]),
			}),
			confidentialClient({ id: "coded", sections: allowed(["authorization_code"]) }),
		]),
		...codeGrantConfig(),
		...refreshConfig(),
	};
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
			simulatedStore().module,
			sessionTokensModule,
			sessionTokensInMemory().module,
			codeGrantModule,
			codeGrantStore,
			refreshModule,
			refreshStore,
			claimsSelectionModule,
			selections.module,
			consenting,
			tokenExchange,
			revocationModule,
		],
		config: { ...config, ...claimsSelectionConfig({ mode: "draining" }) },
		runtime,
	});
	await app.start();
	stops.push(() => app.stop(1000));
	const on = await assemble({
		modules: [claimsSelectionModule, selections.module, consenting],
		config: { ...kernelConfig(), ...claimsSelectionConfig({ mode: "on" }) },
		runtime,
	});
	const { session } = await app.get(sessions).complete(testRequest(), {
		subject: "alice",
		amr: ["pwd"],
		authenticatedAt: runtime.clock.now(),
	});
	const grant = async (grantType: string, as: string, form: Record<string, string>) => {
		const outcome = await app
			.get(grantCalls)
			.call(grantType, as, { grant_type: grantType, ...form });
		return outcome.kind === "issued"
			? ({ ...outcome.body } as Record<string, string>)
			: { error: outcome.error };
	};
	/** A code kept with `selection` by the host still on, then redeemed here: an exchange late in the drain. */
	const redeem = async (as: string, selection?: Selection) => {
		const code = await app.get(codes).issue({
			clientId: as,
			redirectUri: "https://app.example/cb",
			challenge,
			scope: ["read"],
			audience: ["https://api"],
			session: session.id,
			subject: "alice",
		});
		if (selection)
			await on
				.get(claimsSelections)
				.keepForCode(app.get(codes).redemptionOf(code), selection, 600_000);
		return grant("authorization_code", as, {
			code,
			redirect_uri: "https://app.example/cb",
			code_verifier: verifier,
		});
	};
	const active = async (token: string | undefined) =>
		(await app.get(tokens).verifyAccess(token ?? "")).kind === "valid";
	return { app, grant, redeem, active, run: () => app.get(constrainedFamilyRevocation).run() };
}

it("revokes a constrained family founded late in the drain, with every token refreshed or exchanged from it, and no other family", async () => {
	const host = await draining();
	const first = await host.redeem("app", constrained);
	const refreshed = await host.grant("refresh_token", "app", {
		refresh_token: first.refresh_token ?? "",
	});
	const exchanged = await host.grant(exchangeType, "app", {
		subject_token: refreshed.access_token ?? "",
		subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
	});
	const plain = await host.redeem("app");
	for (const token of [first.access_token, refreshed.access_token, exchanged.access_token])
		expect(await host.active(token)).toBe(true);
	expect(await host.run()).toMatchObject({ kind: "run", revoked: 1, expired: 0 });
	for (const token of [first.access_token, refreshed.access_token, exchanged.access_token])
		expect(await host.active(token)).toBe(false);
	expect(
		await host.grant("refresh_token", "app", { refresh_token: refreshed.refresh_token ?? "" }),
	).toEqual({ error: "invalid_grant" });
	expect(
		(await host.grant("refresh_token", "app", { refresh_token: plain.refresh_token ?? "" }))
			.access_token,
	).toEqual(expect.any(String));
});

it("leaves a constrained token with no family to run out by itself", async () => {
	const host = await draining();
	const coded = await host.redeem("coded", constrained);
	expect(coded.refresh_token).toBeUndefined();
	expect(await host.run()).toMatchObject({ kind: "run", revoked: 0 });
	expect(await host.active(coded.access_token)).toBe(true);
});
