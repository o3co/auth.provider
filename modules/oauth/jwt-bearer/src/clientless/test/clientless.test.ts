import { Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { Checked } from "../../assertion/assertion.ts";
import { type IssuerEntry, issuersSetting } from "../../issuers/issuers.ts";
import { bindingOf, identifiedBy, identifiedOf, unidentified } from "../clientless.ts";

const entries = issuersSetting.parse([
	{
		issuer: "https://shared.example",
		subject: "as-is",
		"jwks-uri": "https://shared.example/jwks",
		conditions: { "subject-prefix": "org:acme/" },
		client: "agents",
	},
	{
		issuer: "https://own.example",
		subject: "as-is",
		"jwks-uri": "https://own.example/jwks",
		"accept-any-subject": true,
	},
]);
const entryOf = (issuer: string) => entries.find((e) => e.issuer === issuer);
const verified = (entry: string, sub: string): Checked => ({
	kind: "valid",
	entry,
	sentIssuer: entry,
	subject: sub,
	jti: "j",
	expiresAt: 0,
	header: {},
	claims: { iss: entry, sub },
});
const asIs = async (_entry: string, sub: string) => sub;

describe("the client an assertion identifies for a request naming none", () => {
	it("is its entry's client once its claims meet the entry's conditions and its subject is taken", async () => {
		const told = await identifiedBy(
			verified("https://shared.example", "org:acme/ci"),
			entryOf,
			asIs,
		);
		if (told.kind !== "client") throw new Error("not identified");
		expect(told.client).toBe("agents");
		expect(identifiedOf(told.identified)).toEqual({
			verified: verified("https://shared.example", "org:acme/ci"),
			subject: "org:acme/ci",
		});
		expect(Object.isFrozen(told.identified)).toBe(true);
	});

	it("answers one refusal for whatever fails before its subject is taken", async () => {
		const linked = async () => undefined;
		for (const [checked, subjectOf] of [
			[{ kind: "invalid", reason: "untrusted signer" }, asIs],
			[{ kind: "invalid", reason: "wrong audience" }, asIs],
			// Verified, but of an entry with no client, or meeting none of its conditions, or linked to none.
			[verified("https://own.example", "alice"), asIs],
			[verified("https://shared.example", "org:other/ci"), asIs],
			[verified("https://shared.example", "org:acme/ci"), linked],
		] as const) {
			expect(await identifiedBy(checked as Checked, entryOf, subjectOf)).toEqual(unidentified);
		}
		expect(unidentified).toEqual({
			kind: "error",
			error: "invalid_grant",
			description: "untrusted signer",
		});
	});

	it("throws where its subject cannot be told", async () => {
		const down = async (): Promise<string | undefined> => {
			throw new Unavailable("users");
		};
		await expect(
			identifiedBy(verified("https://shared.example", "org:acme/ci"), entryOf, down),
		).rejects.toBeInstanceOf(Unavailable);
	});

	it("reads back only what it made, never a look-alike", () => {
		const alike = {
			verified: verified("https://shared.example", "org:acme/ci"),
			subject: "org:acme/ci",
		};
		for (const value of [alike, undefined, null, "x"]) expect(identifiedOf(value)).toBeUndefined();
	});
});

describe("an entry and its client, bound both ways", () => {
	const binding = bindingOf(entries);
	const [shared, own] = entries as [IssuerEntry, IssuerEntry];

	it("issues an entry's assertion with a client to that client alone", () => {
		expect(binding.forAnother(shared, "agents")).toBe(false);
		expect(binding.forAnother(shared, "app")).toBe(true);
	});

	it("takes for an entry's client its entry's assertions alone, a delegated issuer's none", () => {
		expect(binding.forAnother(own, "agents")).toBe(true);
		expect(binding.forAnother(undefined, "agents")).toBe(true);
		expect(binding.forAnother(own, "app")).toBe(false);
		expect(binding.forAnother(undefined, "app")).toBe(false);
	});
});
