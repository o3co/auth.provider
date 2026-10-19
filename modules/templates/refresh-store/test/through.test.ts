import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import { type Addition, additions } from "@mod/code-grant";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import refreshModule from "@mod/refresh/module";
import { refreshConfig } from "@mod/refresh/testing";
import secretHashModule from "@mod/secret-hash/module";
import { sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import sessionParticipants from "@mod/session-participants/module";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import tokenControl from "@mod/token-control/module";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import { tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime();
const seen = contract<readonly Addition[]>("additions-seen");
const reader = defineModule({ name: "reader" }, (m) => [
	m.provide(seen).by((c) => c.collect(additions)),
]);

/** The real refresh over this wiring, starting families as a code's redemption would. */
async function boot() {
	const simulated = simulatedStore();
	const allowed = allowancesFor({
		grants: ["authorization_code", "refresh_token"],
		scopes: ["read"],
		audiences: ["https://api"],
	});
	const app = await assemble({
		modules: [
			http,
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
			simulated.module,
			refreshModule,
			wiring,
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
	const { session } = await app.get(sessions).complete(testRequest(), {
		subject: "alice",
		amr: ["pwd"],
		authenticatedAt: runtime.clock.now(),
	});
	const grant = { subject: "alice", issuedTo: "app", audience: ["https://api"], scope: ["read"] };
	const start = async () => {
		const issued = await app.get(tokens).issue({ grant, grantType: "authorization_code" });
		if (issued.kind !== "issued") throw new Error(issued.reason);
		const { token: _, ...access } = issued.access;
		const refresh = app.get(seen).find((a) => a.field === "refresh_token");
		return (await refresh?.issue({
			redemption: `r-${Math.random()}`,
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
	};
	const refresh = async (token: string) => {
		const outcome = await app
			.get(grantCalls)
			.call("refresh_token", "app", { grant_type: "refresh_token", refresh_token: token });
		return outcome.kind === "issued" ? String(outcome.body.refresh_token) : outcome.error;
	};
	const close = () => app.get(sessions).close(session.id);
	return { app, simulated, start, refresh, close };
}

it("rotates once through a lost answer to the rotation, and keeps the rotation through a failover", async () => {
	const { simulated, start, refresh } = await boot();
	const first = await start();
	simulated.beforeNext("replaceIf", "refresh-store.families", async () =>
		simulated.loseNextReply(),
	);
	const next = await refresh(first);
	await simulated.failover();
	expect(await refresh(first)).toBe("invalid_grant");
	expect(await refresh(next)).toBe("invalid_grant");
});

it("leaves one usable token after a lost answer in a refresh and a failover after it", async () => {
	const { simulated, start, refresh } = await boot();
	const first = await start();
	simulated.loseNextReply();
	const next = await refresh(first);
	await simulated.failover();
	expect(await refresh(next)).toMatch(/\./);
});

it("keeps a family a reuse revoked revoked through a failover", async () => {
	const { simulated, start, refresh } = await boot();
	const first = await start();
	const next = await refresh(first);
	expect(await refresh(first)).toBe("invalid_grant");
	await simulated.failover();
	expect(await refresh(next)).toBe("invalid_grant");
});

it("revokes a session's family and its access tokens when the session closes, through refresh's participant", async () => {
	const { app, start, close } = await boot();
	const params = { grant_type: "refresh_token", refresh_token: await start() };
	const outcome = await app.get(grantCalls).call("refresh_token", "app", params);
	if (outcome.kind !== "issued") throw new Error(outcome.error);
	const access = String(outcome.body.access_token);
	expect((await app.get(tokens).verifyAccess(access)).kind).toBe("valid");
	expect((await close()).kind).toBe("closed");
	expect((await app.get(tokens).verifyAccess(access)).kind).toBe("invalid");
});
