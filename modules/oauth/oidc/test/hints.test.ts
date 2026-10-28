import { quietRuntime } from "@mod/kernel/testing";
import { accessTokenSigning, keys } from "@mod/keys";
import { afterEach, expect, it } from "vitest";
import { idTokenHints } from "../src/contract.ts";
import { booted } from "./parts.ts";

const start = 1_800_000_000_000;
let now = start;
const runtime = quietRuntime({ clock: { now: () => now } });
afterEach(() => {
	now = start;
});

async function serve() {
	const app = await booted({ runtime });
	const iat = now / 1000;
	const core = { iss: "https://as.example", sub: "alice", aud: "app", iat, exp: iat + 3600 };
	/** A token signed with the provider's own key, the core claims written over by `over`. */
	const signed = (over: Record<string, unknown> = {}, typ = "JWT") =>
		app.get(keys).sign({ ...core, sid: "s1", ...over }, typ);
	/** An access token the provider signed, the same claims under the access token type. */
	const access = () => app.get(accessTokenSigning).sign({ ...core, sid: "s1" });
	return { check: app.get(idTokenHints).check, signed, access };
}

it("answers the subject, session, client and issue time of an ID token the provider signed", async () => {
	const { check, signed } = await serve();
	expect(await check(await signed())).toEqual({
		kind: "valid",
		subject: "alice",
		session: "s1",
		client: "app",
		issuedAt: now,
	});
});

it("ignores the claims of a hint it does not understand [oidc-core-2-s]", async () => {
	const { check, signed } = await serve();
	const odd = {
		ext: "x",
		nested: { a: [1] },
		nonce: "n",
		acr: "urn:x",
		"https://other.example/c": 1,
	};
	expect(await check(await signed(odd))).toEqual({
		kind: "valid",
		subject: "alice",
		session: "s1",
		client: "app",
		issuedAt: now,
	});
});

it("takes the client from azp when the audience names it, else from a single audience", async () => {
	const { check, signed } = await serve();
	const clientOf = async (over: Record<string, unknown>) => {
		const hint = await check(await signed(over));
		return hint.kind === "valid" ? hint.client : hint.kind;
	};
	expect(await clientOf({ aud: ["app", "api"], azp: "app" })).toBe("app");
	expect(await clientOf({ aud: ["app"] })).toBe("app");
	expect(await clientOf({ aud: ["app", "api"] })).toBeUndefined();
	expect(await clientOf({ aud: "app", azp: "other" })).toBe("app");
	expect(await clientOf({ aud: ["app", "api"], azp: "other" })).toBeUndefined();
	expect(await clientOf({ aud: [7] })).toBeUndefined();
});

it("refuses a token of another kind, issuer or key, or one that does not read", async () => {
	const { check, signed, access } = await serve();
	const refused: Record<string, string> = {
		"another typ": await signed({}, "logout+jwt"),
		"an access token": await access(),
		"another issuer": await signed({ iss: "https://other.example" }),
		"an empty sub": await signed({ sub: "" }),
		"a sub that is not a string": await signed({ sub: 7 }),
		"no iat": await signed({ iat: undefined }),
		"an iat that is not a number": await signed({ iat: "1" }),
		"a broken signature": (await signed()).replace(/\.[^.]+$/, ".AAAA"),
		"not a token": "not-a-token",
	};
	for (const [name, token] of Object.entries(refused)) {
		expect(await check(token), name).toEqual({ kind: "invalid" });
	}
});

it("takes a hint long past its end, but not one that states none", async () => {
	const { check, signed } = await serve();
	const hint = await signed();
	now += 30 * 86_400_000;
	expect((await check(hint)).kind).toBe("valid");
	expect(await check(await signed({ exp: undefined }))).toEqual({ kind: "invalid" });
	expect(await check(await signed({ exp: "1" }))).toEqual({ kind: "invalid" });
});

it("answers a token that names no session apart", async () => {
	const { check, signed } = await serve();
	expect(await check(await signed({ sid: undefined }))).toEqual({ kind: "sessionless" });
	expect(await check(await signed({ sid: "" }))).toEqual({ kind: "sessionless" });
});
