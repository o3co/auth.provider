import type { Client } from "@mod/clients";
import { clientSection } from "@mod/consent";
import type { Session } from "@mod/session";
import { describe, expect, it } from "vitest";
import { consentDecisionWith } from "../consent-decision.ts";

/** A registered client, first-party or not, as `consent`'s section says. */
const clientOf = (id: string, firstParty: boolean): Client => ({
	id,
	kind: "confidential",
	method: "client_secret_basic",
	registered: true,
	section: <T>(section: { name: string }) =>
		(section.name === clientSection.name ? { "first-party": firstParty } : {}) as T,
});

describe("consent-decision", () => {
	it("agrees a scope for a client that asks consent only where the subject agreed to it, and always for a first-party one", async () => {
		const asked: [string, string, readonly string[]][] = [];
		const decision = consentDecisionWith({
			consents: {
				asking: true,
				ask: async () => "https://as.example/consent",
				covers: async (clientId, subject, range) => {
					asked.push([clientId, subject, range]);
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
			consents: { asking: false, ask: async () => "", covers: async () => true },
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
});
