import type { Client, Section } from "@mod/clients";
import type { GrantInput } from "@mod/grants";
import { describe, expect, it } from "vitest";
import { clientCredentials, clientCredentialsGrantType } from "../src/contract.ts";

const issuer = "https://as.example";

/** A client of the kind given, allowed as `allowed` says under client-allowance's section. */
const client = (kind: Client["kind"], allowed: Record<string, unknown> = {}): Client => ({
	id: "svc",
	kind,
	method: kind === "public" ? "none" : "client_secret_basic",
	registered: true,
	section: <T>(section: Section<T>) =>
		(section.name === "client-allowance"
			? { grants: [clientCredentialsGrantType], scopes: [], audiences: [], ...allowed }
			: {}) as T,
});

/** The grant asked with these parameters, issuing what it is given unless the policies refuse. */
async function ask(c: Client, params: Record<string, string> = {}, refused = false) {
	const issued: unknown[] = [];
	const input = {
		client: c,
		param: (name: string) => params[name],
		target: (audience: readonly string[]) => ({ kind: "ok" as const, audience }),
		issue: async (grant: unknown) => {
			issued.push(grant);
			return refused
				? { kind: "refused" as const, policy: "p", description: "no" }
				: {
						kind: "issued" as const,
						access: { token: "t", tokenType: "Bearer", expiresIn: 300 },
					};
		},
	} as unknown as GrantInput;
	return { answer: await clientCredentials(issuer).handle(input), issued };
}

describe("client credentials", () => {
	it("is client_credentials, reading no ambient credential and taking its audience from the request", () => {
		const grant = clientCredentials(issuer);
		expect([grant.grantType, grant.readsAmbient, grant.targets]).toEqual([
			"client_credentials",
			"none",
			true,
		]);
	});

	it("issues a confidential client a token for itself, its default scope and the issuer as audience [rfc6749-4.4.3-a] [rfc6749-5.1-a] [rfc6749-5.1-b] [rfc6749-3.3-a]", async () => {
		const { answer, issued } = await ask(
			client("confidential", { scopes: ["read"], "default-scopes": ["read"] }),
		);
		expect(answer).toEqual({
			kind: "issued",
			body: { access_token: "t", token_type: "Bearer", expires_in: 300, scope: "read" },
		});
		expect(issued).toEqual([
			{ subject: "svc", issuedTo: "svc", audience: [issuer], scope: ["read"] },
		]);
	});

	it("refuses a public client, and a scope outside the allowance, before issuing [rfc6749-4.4-a]", async () => {
		expect((await ask(client("public"))).answer).toEqual({
			kind: "error",
			error: "unauthorized_client",
		});
		const outside = await ask(client("confidential", { scopes: ["read"] }), { scope: "write" });
		expect([outside.answer, outside.issued]).toEqual([
			{ kind: "error", error: "invalid_scope" },
			[],
		]);
	});

	it("answers a refused issuance as the policies refused it", async () => {
		const { answer } = await ask(
			client("confidential", { scopes: ["read"], "default-scopes": ["read"] }),
			{},
			true,
		);
		expect(answer).toMatchObject({ kind: "refused", policy: "p" });
	});
});
