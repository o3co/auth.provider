import { expect, it } from "vitest";
import { upstreamEndSessions } from "../src/contract.ts";
import { harness, type Offered } from "./harness.ts";

/** An upstream whose end of session carries what it was given, unless it throws. */
const ending = (throws = false): Offered => ({
	endSession: (at) => {
		if (throws) throw new Error("no end");
		const url = new URL("https://idp.example/logout");
		for (const [key, value] of Object.entries(at)) url.searchParams.set(key, String(value));
		return url.href;
	},
});
const paramsOf = (url: string | undefined) =>
	url === undefined ? undefined : Object.fromEntries(new URL(url).searchParams);

it("sends a session to its first upstream's end of session, with that login's ID token as the hint", async () => {
	const h = await harness({ offered: ending() });
	const session = await h.login();
	await h.receive(session, { idToken: "id-1" });
	await h.receive(session, {}, "other");
	const of = h.app.get(upstreamEndSessions).of;
	expect(
		paramsOf(await of(session.id, { postLogoutRedirectUri: "https://rp/after", state: "s1" })),
	).toEqual({ idTokenHint: "id-1", postLogoutRedirectUri: "https://rp/after", state: "s1" });
	expect(paramsOf(await of(session.id, {}))).toEqual({ idTokenHint: "id-1" });
	const { token } = await h.issue(session);
	expect((await h.ask(token)).status).toBe(200);
});

it("answers none for a session with no upstream tokens, or whose first upstream has no end", async () => {
	const h = await harness({ offered: ending() });
	const of = h.app.get(upstreamEndSessions).of;
	const plain = await h.login();
	expect(await of(plain.id, {})).toBeUndefined();
	const elsewhere = await h.login();
	await h.receive(elsewhere, {}, "other");
	await h.receive(elsewhere, { idToken: "id-1" });
	expect(await of(elsewhere.id, {})).toBeUndefined();
});

it("answers none when the upstream cannot build its end of session, warning with the IdP and the failure's kind", async () => {
	const h = await harness({ offered: ending(true) });
	const session = await h.login();
	await h.receive(session);
	expect(await h.app.get(upstreamEndSessions).of(session.id, {})).toBeUndefined();
	expect(h.logged().filter((l) => l.event === "federation-tokens.end_session_failed")).toEqual([
		{
			level: "warn",
			event: "federation-tokens.end_session_failed",
			fields: { idp: "corp", kind: "Error" },
		},
	]);
});
