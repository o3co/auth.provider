import type { Client } from "@mod/clients";
import { clientSection } from "@mod/consent";
import type { Session } from "@mod/session";
import { describe, expect, it } from "vitest";
import { consentDecisionWith } from "../consent-decision.ts";

/** A client, first-party or not as `consent`'s section says, registered by the operator unless said. */
const clientOf = (id: string, firstParty: boolean, registered = true): Client => ({
	id,
	kind: "confidential",
	method: "client_secret_basic",
	registered,
	section: <T>(section: { name: string }) =>
		(section.name === clientSection.name ? { "first-party": firstParty } : {}) as T,
});

describe("consent-decision", () => {
	it("hands consent the client it holds, for what it reads and for what it asks", async () => {
		const held: Client[] = [];
		const client = clientOf("third", false);
		const decision = consentDecisionWith({
			consents: {
				asking: true,
				askFor: async (_, one, { range }) => {
					held.push(one);
					return `https://as.example/consent?range=${range.join("+")}`;
				},
				coversFor: async (one) => {
					held.push(one);
					return false;
				},
			},
		});
		const session = { context: { subject: "alice" } } as Session;
		const asked = await decision.decide(client, session, ["read"], new Set(), () => "");
		expect(asked).toEqual({ kind: "send", to: "https://as.example/consent?range=read" });
		await decision.consented(client, "alice", "read");
		expect(held).toEqual([client, client, client]);
		expect(held.every((one) => one === client)).toBe(true);
	});

	it("agrees a scope for a client that asks consent only where the subject agreed to it, and always for a first-party one", async () => {
		const asked: [string, string, readonly string[]][] = [];
		const decision = consentDecisionWith({
			consents: {
				asking: true,
				askFor: async () => "https://as.example/consent",
				coversFor: async (client, subject, range) => {
					asked.push([client.id, subject, range]);
					return range.every((scope) => scope === "read");
				},
			},
		});
		expect(await decision.consented(clientOf("third", false), "alice", "read")).toBe(true);
		expect(await decision.consented(clientOf("third", false), "alice", "write")).toBe(false);
		expect(await decision.consented(clientOf("app", true), "alice", "write")).toBe(true);
		// A first-party client's consent is never read.
		expect(asked).toEqual([
			["third", "alice", ["read"]],
			["third", "alice", ["write"]],
		]);
	});

	it("refuses a client that is not first-party while consent cannot ask, reading no prompt, and serves a first-party one, prompt=consent too [oidc-core-3.1.2.1-o]", async () => {
		const decision = consentDecisionWith({
			consents: { asking: false, askFor: async () => "", coversFor: async () => true },
		});
		expect(decision.served(clientOf("third", false))).toEqual({
			kind: "refuse",
			error: "unauthorized_client",
			reason: "client_not_first_party",
			description: "client is not authorized for the authorization endpoint",
		});
		expect(decision.served(clientOf("app", true))).toBeUndefined();
		// A first-party client needs no consent, so prompt=consent asks nothing it cannot obtain.
		const prompt = new Set(["consent"]);
		const decided = decision.decide(
			clientOf("app", true),
			{} as Session,
			["read"],
			prompt,
			() => "",
		);
		expect(await decided).toBeUndefined();
	});

	it("refuses, recorded, a client from another source that says nothing a grant could be agreed under, as no answer could ever cover it", () => {
		const decision = consentDecisionWith({
			consents: { asking: true, askFor: async () => "", coversFor: async () => false },
		});
		expect(decision.served(clientOf("elsewhere", false, false))).toEqual({
			kind: "refuse",
			error: "unauthorized_client",
			reason: "client_agreed_under_nothing",
			description: "client is not authorized for the authorization endpoint",
		});
		const under = (client: Client): Client => ({
			...client,
			section: <T>() => ({ "first-party": false, under: "d1" }) as T,
		});
		expect(decision.served(under(clientOf("documented", false, false)))).toBeUndefined();
		expect(decision.served(clientOf("named", false))).toBeUndefined();
	});

	it("refuses a silent request with consent_required, so no code, unless its client is first-party or the subject agreed to its whole scope [rfc9700-4.11.2-a]", async () => {
		const decision = consentDecisionWith({
			consents: {
				asking: true,
				askFor: async () => "https://as.example/consent",
				coversFor: async (_, __, range) => range.every((scope) => scope === "read"),
			},
		});
		const session = { context: { subject: "alice" } } as Session;
		const silent = (client: Client, scope: readonly string[]) =>
			decision.decide(client, session, scope, new Set(["none"]), () => "");
		const required = { kind: "refuse", error: "consent_required", reason: "consent_required" };
		expect(await silent(clientOf("third", false), ["read", "write"])).toMatchObject(required);
		// A client a source names is never first-party, whatever its section says.
		expect(await silent(clientOf("named", true, false), ["write"])).toMatchObject(required);
		expect(await silent(clientOf("third", false), ["read"])).toBeUndefined();
		expect(await silent(clientOf("app", true), ["write"])).toBeUndefined();
	});
});
