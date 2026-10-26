import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { converse } from "../src/dialog/dialog.ts";
import type { Flow } from "../src/libraries/libraries.ts";
import { excusable, library, runs, unmetOf } from "./library.ts";
import { type ServicesWorld, startServicesWorld } from "./world/services.ts";

/** The flows of this file: those of services, which need no user. */
const here: Flow[] = ["jwt-bearer", "jwt-bearer-no-client", "id-jag"];

let world: ServicesWorld;
beforeAll(async () => {
	if (here.some(runs)) world = await startServicesWorld();
});
afterAll(async () => {
	await world?.stop();
});

/** Runs one flow with the library; it asks nothing of a browser, and one that gives no result fails. */
async function run(flow: Flow, extra: Record<string, unknown>) {
	const dialog = await converse(
		library.adapter(),
		{ flow, issuer: world.issuer, ca: world.ca, ...extra },
		async (ask) => {
			throw new Error(`the driver has no answer to ${ask.ask}`);
		},
		90_000,
	);
	if (dialog.outcome.kind !== "result")
		throw new Error(
			`${library.name} ${flow}: ${dialog.outcome.type}: ${dialog.outcome.message}\n${dialog.stderr.slice(-2000)}`,
		);
	return dialog.outcome.result as Record<string, unknown>;
}

describe(`${library.name}: an assertion for a token`, () => {
	it.runIf(runs("jwt-bearer"))(
		"gets a token by the jwt-bearer grant, its assertion from an issuer the provider trusts, the client authenticated",
		(context) =>
			excusable(context, "jwt-bearer", async () => {
				const result = await run("jwt-bearer", {
					client: world.clients.bearer,
					assertionIssuer: world.assertionIssuer,
					subject: "service-a",
					scope: "read",
					// No OpenID discovery here: the OAuth metadata (RFC 8414), for an adapter that reads one.
					metadata: "oauth-authorization-server",
				});
				expect(String(result.tokenType).toLowerCase()).toBe("bearer");
				expect(String(result.accessToken)).not.toBe("");
			}),
	);
});

describe(`${library.name}: an assertion for a token, naming no client`, () => {
	it.runIf(runs("jwt-bearer-no-client"))(
		"gets a token by the jwt-bearer grant with no client authentication, for the client its issuer's entry names",
		(context) =>
			excusable(context, "jwt-bearer-no-client", async () => {
				const result = await run("jwt-bearer-no-client", {
					client: world.clients.agents,
					assertionIssuer: world.clientlessIssuer,
					subject: `${world.clientlessIssuer.subjectPrefix}ci`,
					scope: "read",
					metadata: "oauth-authorization-server",
				});
				expect(String(result.tokenType).toLowerCase()).toBe("bearer");
				// Issued to the client the issuer's entry names, though the request named none (RFC 9068 §2.2).
				const [, payload = ""] = String(result.accessToken).split(".");
				const claims = JSON.parse(Buffer.from(payload, "base64url").toString()) as Record<
					string,
					unknown
				>;
				expect([claims.client_id, claims.sub]).toEqual([
					world.clients.agents.id,
					`${world.clientlessIssuer.subjectPrefix}ci`,
				]);
			}),
	);
});

describe(`${library.name}: an ID-JAG from an enterprise IdP, for a token`, () => {
	/** Gets an ID-JAG from the played IdP by token exchange, then a token for it here by jwt-bearer. */
	const exchanged = (dpop = false) =>
		converse(
			library.adapter(),
			{
				flow: "id-jag",
				issuer: world.issuer,
				ca: world.ca,
				idp: { issuer: world.idp.issuer, ca: world.idp.ca },
				client: world.clients.jagAgent,
				// The user's ID token at the IdP, which the played IdP does not read.
				subjectToken: "played-id-token",
				scope: "read",
				dpop,
			},
			async (ask) => {
				throw new Error(`the driver has no answer to ${ask.ask}`);
			},
			90_000,
		).then((d) => d.outcome);

	it.runIf(runs("id-jag"))(
		"gets an ID-JAG for this provider by token exchange, and a token for it by jwt-bearer, its scope and resource answered",
		async () => {
			const outcome = await exchanged();
			expect(outcome).toMatchObject({ kind: "result" });
			const result = (outcome as { result: Record<string, unknown> }).result;
			expect(String(result.tokenType).toLowerCase()).toBe("bearer");
			expect([result.scope, result.resource]).toEqual(["read", world.issuer]);
		},
	);

	it.runIf(runs("id-jag"))(
		"binds the token to the DPoP key the ID-JAG names, proved by the client at both",
		async () => {
			const outcome = await exchanged(true);
			expect(outcome).toMatchObject({ kind: "result", result: { tokenType: "DPoP" } });
		},
	);

	it.runIf(runs("id-jag"))(
		"is refused an ID-JAG for another client, of another type, or for another audience",
		async () => {
			for (const otherwise of [
				{ clientId: "someone-else" },
				{ typ: "JWT" },
				{ aud: "https://another-as.example" },
			]) {
				world.idp.otherwise(otherwise);
				expect(await exchanged(), JSON.stringify(otherwise)).toMatchObject({
					kind: "error",
					type: "invalid_grant",
				});
			}
		},
	);
});

describe(`${library.name}: the known differences of services`, () => {
	it("are each met by a check of this run, so a fixed one is taken out", () => {
		expect(unmetOf(here)).toEqual([]);
	});
});
