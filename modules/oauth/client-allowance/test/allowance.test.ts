import type { Client } from "@mod/clients";
import { describe, expect, it } from "vitest";
import { clientAllowance } from "../src/contract.ts";
import { type Allowances, allowances } from "../src/metadata.ts";

/** A client whose `client-allowance` section holds these values. */
const holding = (section: Partial<Allowances>): Client => ({
	id: "c",
	kind: "confidential",
	method: "client_secret_basic",
	registered: true,
	section: <T>() => ({ grants: [], scopes: [], audiences: [], ...section }) as T,
});

describe("client allowance", () => {
	it("allows any audience the client is allowed, not only the first", () => {
		const { allowsAudience } = clientAllowance;
		const api = holding({ audiences: ["https://api", "https://other"] });
		expect(allowsAudience(api, "https://api", "https://as")).toBe(true);
		expect(allowsAudience(api, "https://other", "https://as")).toBe(true);
		expect(allowsAudience(api, "https://elsewhere", "https://as")).toBe(false);
		expect(allowsAudience(api, "https://as", "https://as")).toBe(false);
		expect(allowsAudience(api, "c", "https://as")).toBe(false);
	});

	it("allows only the issuer as the audience of a client allowed none", () => {
		const { allowsAudience } = clientAllowance;
		expect(allowsAudience(holding({}), "https://as", "https://as")).toBe(true);
		expect(allowsAudience(holding({}), "https://api", "https://as")).toBe(false);
	});
});

describe("allowances within a ceiling", () => {
	const { allowancesWithin, allowsGrant, allowsAudience, allowedIssuance } = clientAllowance;
	const ceiling = {
		grants: ["authorization_code", "refresh_token"],
		scopes: ["read", "write"],
		audiences: ["https://api"],
	};
	/** A client holding the section the answer places, read as the clients' records are. */
	const placed = (entry: Readonly<Record<string, unknown>> | undefined) => {
		if (entry === undefined) throw new Error("refused");
		const checked = allowances.schema["~standard"].validate(entry[allowances.name]);
		if (checked instanceof Promise || checked.issues) throw new Error("not a section value");
		return holding(checked.value);
	};

	it("keeps only what the ceiling also holds", () => {
		const client = placed(
			allowancesWithin(ceiling, {
				grants: ["authorization_code", "client_credentials"],
				scopes: ["read", "admin"],
			}),
		);
		expect(allowsGrant(client, "authorization_code")).toBe(true);
		expect(clientAllowance.grantsOf(client)).toEqual(client.section(allowances).grants);
		expect(allowsGrant(client, "client_credentials")).toBe(false);
		expect(allowsGrant(client, "refresh_token")).toBe(false);
		expect(allowedIssuance(client, "admin", "https://as").kind).toBe("error");
		expect(allowedIssuance(client, "write", "https://as").kind).toBe("error");
		expect(allowedIssuance(client, "read", "https://as")).toMatchObject({ scope: ["read"] });
	});

	it("takes the whole ceiling for a list not asked", () => {
		const client = placed(allowancesWithin(ceiling, { grants: ["authorization_code"] }));
		expect(allowedIssuance(client, "read write", "https://as")).toEqual({
			kind: "allowed",
			scope: ["read", "write"],
			audience: ["https://api"],
		});
		expect(allowsAudience(client, "https://api", "https://as")).toBe(true);
	});

	it("never widens the ceiling, even with an empty one", () => {
		const nothing = { grants: [], scopes: [], audiences: [] };
		const client = placed(
			allowancesWithin(nothing, { grants: ["authorization_code"], scopes: ["read"] }),
		);
		expect(allowsGrant(client, "authorization_code")).toBe(false);
		expect(allowedIssuance(client, "read", "https://as").kind).toBe("error");
		const issuer = "https://as";
		for (const audiences of [[], ["https://api"], ["https://api", issuer]]) {
			for (const asked of [undefined, [], ["https://api"], ["https://other"], [issuer]]) {
				const entry = allowancesWithin(
					{ ...nothing, audiences },
					asked ? { audiences: asked } : {},
				);
				if (entry === undefined) continue;
				for (const audience of [issuer, "https://api", "https://other"]) {
					const widened =
						allowsAudience(placed(entry), audience, issuer) &&
						!allowsAudience(holding({ audiences }), audience, issuer);
					expect(widened, `${audience} within ${audiences} asking ${asked}`).toBe(false);
				}
			}
		}
	});

	it("refuses asked audiences that leave none of a ceiling naming some, as none would mean the issuer", () => {
		expect(allowancesWithin(ceiling, { audiences: ["https://other"] })).toBeUndefined();
		expect(allowancesWithin(ceiling, { audiences: [] })).toBeUndefined();
		const open = placed(
			allowancesWithin({ ...ceiling, audiences: [] }, { audiences: ["https://api"] }),
		);
		expect(allowsAudience(open, "https://as", "https://as")).toBe(true);
		expect(allowsAudience(open, "https://api", "https://as")).toBe(false);
	});
});

describe("scope parameter", () => {
	const { parseScope, allowedIssuance } = clientAllowance;

	it("reads an empty value as naming no scope, as when it is left out (RFC 6749 §3.2)", () => {
		expect(parseScope("")).toEqual([]);
		expect(parseScope(undefined)).toEqual([]);
		expect(parseScope("read write")).toEqual(["read", "write"]);
	});

	it("refuses a value that is not scope tokens joined by single spaces (RFC 6749 §3.3)", () => {
		for (const raw of [" ", " read", "read ", "read  write", "read\twrite", 'say"hi']) {
			expect(parseScope(raw)).toBeUndefined();
		}
	});

	it("issues the defaults for an empty scope, as for none [rfc6749-3.3-b]", () => {
		const client = holding({ scopes: ["read", "write"], "default-scopes": ["read"] });
		for (const requested of ["", undefined]) {
			expect(allowedIssuance(client, requested, "https://as")).toEqual({
				kind: "allowed",
				scope: ["read"],
				audience: ["https://as"],
			});
		}
		const required = holding({ scopes: ["read"] });
		expect(allowedIssuance(required, "", "https://as")).toMatchObject({ error: "invalid_scope" });
	});
});

describe("grants, scopes, issuances and audiences seen", () => {
	const { allowsGrant, allowsScope, covers, maySee } = clientAllowance;

	it("answers whether a client may use a grant, by what its allowance names", () => {
		const client = (grants: string[]) => holding({ grants });
		expect(allowsGrant(client(["refresh_token"]), "refresh_token")).toBe(true);
		expect(allowsGrant(client(["client_credentials"]), "refresh_token")).toBe(false);
		expect(allowsGrant(client([]), "client_credentials")).toBe(false);
	});

	it("issues each scope asked once, the first allowed audience, and no scope to a client allowed none, never past its allowance [rfc6750-5.2-c] [rfc9700-2.3-a]", () => {
		const { allowedIssuance } = clientAllowance;
		const client = holding({ scopes: ["read"], audiences: ["https://api", "https://other"] });
		expect(allowedIssuance(client, "read read", "https://as")).toEqual({
			kind: "allowed",
			scope: ["read"],
			audience: ["https://api"],
		});
		expect(allowedIssuance(client, "read write", "https://as")).toMatchObject({
			error: "invalid_scope",
		});
		expect(allowedIssuance(holding({}), undefined, "https://as")).toEqual({
			kind: "allowed",
			scope: [],
			audience: ["https://as"],
		});
	});

	it("answers whether a client may be issued one scope, by what its allowance names", () => {
		const client = holding({ scopes: ["read", "write"], "default-scopes": ["read"] });
		expect([allowsScope(client, "read"), allowsScope(client, "write")]).toEqual([true, true]);
		expect([allowsScope(client, "admin"), allowsScope(client, "")]).toEqual([false, false]);
	});

	it("answers whether an earlier issuance is covered by a client's allowance, and whether a client may see an audience", () => {
		const client = (audiences: string[]) => holding({ scopes: ["read"], audiences });
		const api = client(["https://api", "https://other"]);
		expect(covers(api, { scope: ["read"], audience: ["https://api"] }, "https://as")).toBe(true);
		expect(covers(api, { scope: ["admin"], audience: ["https://api"] }, "https://as")).toBe(false);
		// Any one audience the client may have, so a token narrowed to its second passes.
		expect(covers(api, { scope: [], audience: ["https://other"] }, "https://as")).toBe(true);
		expect(covers(api, { scope: [], audience: ["https://elsewhere"] }, "https://as")).toBe(false);
		expect(
			covers(api, { scope: [], audience: ["https://api", "https://other"] }, "https://as"),
		).toBe(false);
		expect(covers(client([]), { scope: [], audience: ["https://as"] }, "https://as")).toBe(true);
		expect(maySee(api, ["https://other"])).toBe(true);
		expect(maySee(api, ["c"])).toBe(true);
		expect(maySee(api, ["https://elsewhere"])).toBe(false);
	});
});

describe("an issuance within ceilings", () => {
	const { allowedIssuance, allowedIssuanceWithin, allowsAudienceWithin } = clientAllowance;
	const as = "https://as";
	const client = holding({
		scopes: ["read", "write"],
		audiences: ["https://api", "https://other"],
		"default-scopes": ["read", "write"],
	});

	it("decides as allowedIssuance with no ceiling", () => {
		for (const asked of [undefined, "", "read", "write read", "admin"]) {
			expect(allowedIssuanceWithin(client, [], asked, as), String(asked)).toEqual(
				allowedIssuance(client, asked, as),
			);
		}
	});

	it("keeps what every ceiling and the client hold, a list not written being no ceiling", () => {
		const ceilings = [
			{ scopes: ["read", "write", "admin"] },
			{ scopes: ["read"], audiences: ["https://other"] },
		];
		expect(allowedIssuanceWithin(client, ceilings, "read", as)).toEqual({
			kind: "allowed",
			scope: ["read"],
			audience: ["https://other"],
		});
		expect(allowedIssuanceWithin(client, ceilings, "write", as)).toMatchObject({
			kind: "error",
			error: "invalid_scope",
		});
		expect(allowedIssuanceWithin(client, ceilings, "admin", as).kind).toBe("error");
		// The defaults are narrowed too; one the ceilings leave none of is refused, never issued empty.
		expect(allowedIssuanceWithin(client, ceilings, undefined, as)).toMatchObject({
			scope: ["read"],
		});
		expect(allowedIssuanceWithin(client, [{ scopes: ["admin"] }], undefined, as)).toMatchObject({
			kind: "error",
			error: "invalid_scope",
		});
	});

	it("allows nothing under an empty list, and never widens what the client is allowed", () => {
		expect(allowedIssuanceWithin(client, [{ scopes: [] }], "read", as).kind).toBe("error");
		expect(allowedIssuanceWithin(client, [{ scopes: [] }], undefined, as).kind).toBe("error");
		expect(allowedIssuanceWithin(client, [{ audiences: [] }], "read", as)).toMatchObject({
			kind: "error",
			error: "invalid_target",
		});
		expect(
			allowedIssuanceWithin(client, [{ audiences: ["https://elsewhere"] }], "read", as),
		).toMatchObject({
			kind: "error",
			error: "invalid_target",
		});
		const wide = [
			{ scopes: ["read", "write", "admin"], audiences: ["https://api", "https://elsewhere"] },
		];
		expect(allowedIssuanceWithin(client, wide, "admin", as).kind).toBe("error");
		expect(allowsAudienceWithin(client, wide, "https://elsewhere", as)).toBe(false);
	});

	it("holds the issuer, a client's audience when it is allowed none, to the ceilings like any other", () => {
		const bare = holding({ scopes: ["read"] });
		expect(allowedIssuanceWithin(bare, [{ audiences: [as] }], "read", as)).toMatchObject({
			audience: [as],
		});
		expect(allowedIssuanceWithin(bare, [{ audiences: ["https://api"] }], "read", as)).toMatchObject(
			{
				kind: "error",
				error: "invalid_target",
			},
		);
		expect(allowsAudienceWithin(bare, [{ audiences: ["https://api"] }], as, as)).toBe(false);
		expect(allowsAudienceWithin(bare, [{ scopes: ["read"] }], as, as)).toBe(true);
	});

	it("keeps an explicitly empty default within any ceiling", () => {
		const none = holding({ scopes: ["read"], "default-scopes": [] });
		expect(allowedIssuanceWithin(none, [{ scopes: [] }], undefined, as)).toMatchObject({
			kind: "allowed",
			scope: [],
		});
	});
});

describe("ceilings never widen an issuance", () => {
	const { allowedIssuance, allowedIssuanceWithin } = clientAllowance;
	const as = "https://as";
	const clients = [
		holding({ scopes: ["read"] }),
		holding({ scopes: ["read", "write"], "default-scopes": ["read"] }),
		holding({ scopes: ["read"], "default-scopes": [] }),
		holding({ scopes: [], audiences: ["https://api"] }),
		holding({ scopes: ["read"], audiences: ["https://api", "https://other"] }),
	];
	const ceilings = [
		[{ scopes: [] }],
		[{ scopes: ["admin"] }],
		[{ scopes: ["read"] }],
		[{ audiences: [] }],
		[{ audiences: [as] }],
		[{ scopes: ["read", "write"], audiences: ["https://other"] }],
		[{ scopes: ["read"] }, { scopes: [] }],
	];

	it("refuses a client that must name a scope and names none, under any ceiling", () => {
		const must = holding({ scopes: ["read"] });
		expect(allowedIssuance(must, undefined, as).kind).toBe("error");
		for (const within of ceilings) {
			for (const asked of [undefined, ""]) {
				expect(
					allowedIssuanceWithin(must, within, asked, as),
					JSON.stringify(within),
				).toMatchObject({ kind: "error", error: "invalid_scope" });
			}
		}
	});

	it("refuses under every ceiling what it refuses under none, and allows only what it would", () => {
		for (const client of clients) {
			for (const asked of [undefined, "", "read", "write", "read write", "admin"]) {
				const alone = allowedIssuance(client, asked, as);
				for (const within of ceilings) {
					const narrowed = allowedIssuanceWithin(client, within, asked, as);
					const label = JSON.stringify({ section: client.section(allowances), asked, within });
					if (alone.kind === "error") expect(narrowed.kind, label).toBe("error");
					if (narrowed.kind === "allowed") {
						expect(alone.kind, label).toBe("allowed");
						const allowed = client.section(allowances);
						for (const s of narrowed.scope) expect(allowed.scopes, label).toContain(s);
						const reach = allowed.audiences.length > 0 ? allowed.audiences : [as];
						for (const a of narrowed.audience) expect(reach, label).toContain(a);
					}
				}
			}
		}
	});
});
