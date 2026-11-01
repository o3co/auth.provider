import { createHash } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientSecret, clientsConfig, confidentialClient } from "@mod/clients/testing";
import { codes } from "@mod/code-grant";
import codeGrantModule from "@mod/code-grant/module";
import { codeGrantConfig } from "@mod/code-grant/testing";
import cookiesModule from "@mod/cookies/module";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import secretHashModule from "@mod/secret-hash/module";
import senderBindingModule from "@mod/sender-binding/module";
import { sessions } from "@mod/session";
import { openedOf } from "@mod/session/testing";
import sessionLifecycle from "@mod/session-lifecycle/module";
import { sessionLifecycleConfig } from "@mod/session-lifecycle/testing";
import sessionParticipants from "@mod/session-participants/module";
import sessionRequirements from "@mod/session-requirements/module";
import sessionStore from "@mod/session-store/module";
import bridgeModule from "@mod/session-tokens/module";
import sessionTokensStore from "@mod/session-tokens-store/module";
import { simulatedStore } from "@mod/store/testing";
import revocationModule from "@mod/subject-revocation/module";
import revocationStore from "@mod/subject-revocation-store/module";
import tokenEndpoint from "@mod/token-endpoint/module";
import { tokens } from "@mod/tokens";
import tokensModule from "@mod/tokens/module";
import { tokensConfig } from "@mod/tokens/testing";
import tokensStore from "@mod/tokens-store/module";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime();
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");

it("redeems a code once through code-grant wired to records, and revokes what it gave when it comes again [rfc6749-4.1.2-d] [rfc6749-4.1.2-e]", async () => {
	const app = await assemble({
		modules: [
			http,
			keysModule,
			tokensModule,
			tokensStore,
			issuerModule,
			senderBindingModule,
			clientsModule,
			secretHashModule,
			clientAllowanceModule,
			tokenEndpoint,
			rateLimitStandIn,
			auditStandIn().module,
			sessionLifecycle,
			sessionRequirements,
			sessionParticipants,
			cookiesModule,
			sessionStore,
			revocationModule,
			revocationStore,
			simulatedStore().module,
			bridgeModule,
			sessionTokensStore,
			codeGrantModule,
			wiring,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			...keysConfig(),
			...issuerConfig({ url: "https://as.example" }),
			...tokensConfig({ revocation: "denylist" }),
			...clientsConfig([
				confidentialClient({
					id: "app",
					sections: allowancesFor({
						grants: ["authorization_code"],
						scopes: ["read"],
						audiences: ["https://api"],
					}),
				}),
			]),
			...sessionLifecycleConfig(),
			...codeGrantConfig(),
		},
		runtime,
	});
	await app.start();
	try {
		const { session } = openedOf(
			await app.get(sessions).open(testRequest(), {
				subject: "alice",
				amr: ["pwd"],
				authenticatedAt: runtime.clock.now(),
			}),
		);
		const code = await app.get(codes).issue({
			clientId: "app",
			redirectUri: "https://app.example/cb",
			challenge,
			scope: ["read"],
			audience: ["https://api"],
			session: session.id,
			subject: "alice",
		});
		const redeem = async () => {
			const res = await fetch(`http://127.0.0.1:${app.get(listening).port()}/oauth/token`, {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					grant_type: "authorization_code",
					client_id: "app",
					client_secret: clientSecret("app"),
					code,
					redirect_uri: "https://app.example/cb",
					code_verifier: verifier,
				}),
			});
			return { status: res.status, body: (await res.json()) as Record<string, unknown> };
		};
		const first = await redeem();
		expect(first.status).toBe(200);
		expect((await redeem()).body.error).toBe("invalid_grant");
		const verified = await app.get(tokens).verifyAccess(String(first.body.access_token));
		expect(verified.kind).toBe("invalid");
	} finally {
		await app.stop(1000);
	}
});
