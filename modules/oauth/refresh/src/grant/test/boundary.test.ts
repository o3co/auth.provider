import { createHash } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import { selectionConsents } from "@mod/claims-selection";
import claimsSelectionModule from "@mod/claims-selection/module";
import { claimsSelectionInMemory } from "@mod/claims-selection/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import { type Client, clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import { codes } from "@mod/code-grant";
import codeGrantModule from "@mod/code-grant/module";
import { codeGrantConfig } from "@mod/code-grant/testing";
import codeGrantStore from "@mod/code-grant-store/module";
import type { GrantOutcome } from "@mod/grants";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, defineModule, kernelConfig, type Module, Unavailable } from "@mod/kernel";
import { quietRuntime, switchedModule } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import secretHashModule from "@mod/secret-hash/module";
import { sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import sessionParticipants from "@mod/session-participants/module";
import sessionRequirements from "@mod/session-requirements/module";
import sessionTokensModule from "@mod/session-tokens/module";
import { sessionTokensInMemory } from "@mod/session-tokens/testing";
import { simulatedStore } from "@mod/store/testing";
import { revocationFollowers, subjectRevocation } from "@mod/subject-revocation";
import { laggingRevocation } from "@mod/subject-revocation/testing";
import tokenControl from "@mod/token-control/module";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import { issuancePolicies, subjectChecks, type Tokens, tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { afterEach, expect, it } from "vitest";
import { memoryStores } from "../../../test/stores.ts";
import { lineage } from "../../contract.ts";
import refreshModule from "../../module.ts";
import { refreshConfig } from "../../testing.ts";

/** How far the composition's clock runs ahead of the host's. */
let shift = 0;
const runtime = quietRuntime({ clock: { now: () => Date.now() + shift } });
let stop = async () => {};
afterEach(async () => {
	shift = 0;
	await stop();
});
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");

/** A subject check comparing a token's standing time with its subject's boundary, as subject-tokens does. */
const standingChecked = defineModule(
	{ name: "standing-check", replicaSafe: false, takes: [subjectRevocation] },
	(m) => [
		m.contribute(subjectChecks).by(async (c) => {
			const revocation = await c.get(subjectRevocation);
			return {
				holds: async (t) =>
					(await revocation.check(t.subject, t.standingAt)) === "valid" ? "holds" : "revoked",
			};
		}),
	],
);
const agreeing = defineModule({ name: "agreeing", replicaSafe: false, takes: [] }, (m) => [
	m.contribute(selectionConsents).by(() => ({ consented: async () => true })),
]);
/** session's stand-in, its revocation follower failing, as one that cannot read the subject's sessions: none is closed. */
const unfollowed: Module = {
	...sessionStandIn,
	contributes: (sessionStandIn.contributes ?? []).map((part) =>
		part.point === revocationFollowers
			? {
					point: part.point,
					create: () => ({
						name: "session",
						follow: async () => {
							throw new Unavailable("session");
						},
					}),
				}
			: part,
	),
};

/** refresh over the code grant and stand-ins, its subject's boundary read through `lagging`. */
async function serve(
	lagging: ReturnType<typeof laggingRevocation>,
	session: Module = sessionStandIn,
	extra: readonly Module[] = [],
) {
	/** Each access token issued, in order. */
	const issued: string[] = [];
	const capturing = {
		wrap: (inner: Tokens): Tokens => ({
			...inner,
			issue: async (...args) => {
				const out = await inner.issue(...args);
				if (out.kind === "issued") issued.push(out.access.token);
				return out;
			},
		}),
	};
	const both = ["authorization_code", "refresh_token"];
	const app = await assemble({
		modules: [
			http,
			switchedModule(tokensStandIn({ revocable: true }), tokens, capturing as never),
			issuerModule,
			clientsModule,
			secretHashModule,
			grantCaller,
			clientAllowanceModule,
			tokenControl,
			rateLimitStandIn,
			auditStandIn().module,
			sessionRequirements,
			sessionParticipants,
			lagging.module,
			simulatedStore().module,
			sessionTokensModule,
			sessionTokensInMemory().module,
			codeGrantModule,
			codeGrantStore,
			refreshModule,
			memoryStores().module,
			claimsSelectionModule,
			claimsSelectionInMemory().module,
			agreeing,
			standingChecked,
			session,
			...extra,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			...issuerConfig({ url: "https://as.example" }),
			...clientsConfig([
				confidentialClient({
					id: "app",
					sections: allowancesFor({ grants: both, scopes: ["read"], audiences: ["https://api"] }),
				}),
			]),
			...codeGrantConfig(),
			...refreshConfig({ lifetime: "3600s", "sweep-interval": "1s" }),
		},
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const call = (grantType: string, params: Record<string, string>): Promise<GrantOutcome> =>
		app.get(grantCalls).call(grantType, "app", { grant_type: grantType, ...params });
	const bodyOf = (outcome: GrantOutcome) => {
		if (outcome.kind !== "issued") throw new Error(`${outcome.error}: ${outcome.description}`);
		return {
			access: String(outcome.body.access_token),
			refresh: String(outcome.body.refresh_token),
		};
	};
	/** A code redeemed in a session opened now: its family is bound to that session. */
	const redeem = async () => {
		const { session } = await app.get(sessions).complete(testRequest(), {
			subject: "alice",
			amr: ["pwd"],
			authenticatedAt: runtime.clock.now(),
		});
		const code = await app.get(codes).issue({
			clientId: "app",
			redirectUri: "https://app.example/cb",
			challenge,
			scope: ["read"],
			audience: ["https://api"],
			session: session.id,
			subject: "alice",
		});
		const params = { code, redirect_uri: "https://app.example/cb", code_verifier: verifier };
		return bodyOf(await call("authorization_code", params));
	};
	/** A family bound to no session, as another grant starts one. */
	const unbound = async () => {
		const client = (await app.get(clients).find("app")) as Client;
		const grant = { subject: "alice", issuedTo: "app", audience: ["https://api"], scope: ["read"] };
		const first = await app.get(tokens).issue({ grant, grantType: "test" });
		if (first.kind !== "issued") throw new Error(first.reason);
		const { token: _, ...access } = first.access;
		const base = { client, subject: "alice", scope: ["read"], audience: ["https://api"] };
		return app.get(lineage).start({ ...base, authenticatedAt: Date.now(), amr: ["hwk"], access });
	};
	const refresh = (token: string | undefined) =>
		call("refresh_token", { refresh_token: token ?? "" });
	const verify = (token: string) => app.get(tokens).verifyAccess(token);
	return { app, issued, bodyOf, redeem, unbound, refresh, verify };
}

it("issues on a stale read of its subject's boundary a token the next verification refuses, as an unbound family's stands from its authentication [guarantee-4-a]", async () => {
	const lagging = laggingRevocation();
	const s = await serve(lagging);
	const token = await s.unbound();
	shift += 1000;
	lagging.lag();
	await s.app.get(subjectRevocation).revoke("alice");
	// Issued in a later second than the boundary, the family's authentication before it.
	shift += 1500;
	const next = s.bodyOf(await s.refresh(token));
	lagging.catchUp();
	expect(await s.verify(next.access)).toEqual({ kind: "invalid", reason: "revoked" });
});

it("refuses a round whose boundary read came late, where its session no longer enters once the token is issued, revoking that token [guarantee-4-a]", async () => {
	const lagging = laggingRevocation();
	// The boundary's read answers as it stood before, until the policies judge the token.
	const catching = { on: false };
	const policy = defineModule({ name: "catching-up", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(issuancePolicies).by(() => ({
			name: "catching-up",
			judge: async () => {
				if (catching.on) lagging.catchUp();
				return { kind: "allowed" as const };
			},
		})),
	]);
	const s = await serve(lagging, unfollowed, [policy]);
	const first = await s.redeem();
	shift += 1000;
	lagging.lag();
	// The follower that would close the session fails, so the session stays open.
	await s.app
		.get(subjectRevocation)
		.revoke("alice")
		.catch(() => undefined);
	shift += 1500;
	catching.on = true;
	const before = s.issued.length;
	expect(await s.refresh(first.refresh)).toMatchObject({ kind: "error", error: "invalid_grant" });
	const issued = s.issued.slice(before);
	expect(issued).toHaveLength(1);
	expect(await s.verify(issued[0] ?? "")).toEqual({ kind: "invalid", reason: "revoked" });
});
