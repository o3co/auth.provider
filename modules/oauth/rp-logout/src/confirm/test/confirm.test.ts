import type { AuditRecord } from "@mod/audit";
import type { Client } from "@mod/clients";
import type { HttpRequest, HttpResponse } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import type { CloseOutcome } from "@mod/session";
import { describe, expect, it } from "vitest";
import { closingWith } from "../../closing/closing.ts";
import { confirmPath, confirmWith } from "../confirm.ts";

const issuer = "https://as.example";
const confirmUrl = `${issuer}${confirmPath}`;
const logoutUrl = `${issuer}/oauth/logout`;
const nowMs = 1_800_000_000_000;
const nowS = Math.floor(nowMs / 1000);

/** A signer that keeps the claims readable, so each claim can be made wrong on its own. */
const keys = {
	sign: async (claims: Readonly<Record<string, unknown>>, typ: string) =>
		`signed.${Buffer.from(JSON.stringify({ typ, claims })).toString("base64url")}`,
	verify: async (token: string, typ: string) => {
		if (!token.startsWith("signed.")) return { kind: "invalid", reason: "signature" } as const;
		const read = JSON.parse(Buffer.from(token.slice(7), "base64url").toString());
		return read.typ === typ
			? ({ kind: "valid", claims: read.claims } as const)
			: ({ kind: "invalid", reason: "typ" } as const);
	},
};
const signed = (claims: Record<string, unknown>, typ = "logout-confirm+jwt") =>
	`signed.${Buffer.from(JSON.stringify({ typ, claims })).toString("base64url")}`;
const valid = (sid: string, more: Record<string, unknown> = {}) =>
	signed({ iss: issuer, aud: confirmUrl, sid, exp: nowS + 300, ...more });

function serve(
	options: {
		readonly close?: (id: string) => Promise<CloseOutcome>;
		readonly upstream?: string;
		readonly issue?: () => { field: string; token: string; cookies: string[] };
	} = {},
) {
	let at = nowMs;
	/** Each client and the returns it registers, as its record says at the time it is read. */
	const returns = new Map<string, string[]>([["app", ["https://app.example/after"]]]);
	const clientOf = (id: string): Client | undefined => {
		const listed = returns.get(id);
		if (listed === undefined) return undefined;
		const section = { "post-logout-redirect-uris": listed };
		return {
			id,
			kind: "confidential",
			method: "client_secret_basic",
			registered: true,
			section: <T>() => section as T,
		};
	};
	const closes: string[] = [];
	/** The return the upstream's end of session was handed, on each close. */
	const upstreamBacks: unknown[] = [];
	const recorded: AuditRecord[] = [];
	const logged = recordingLog();
	const closing = closingWith({
		sessions: {
			close: async (id) => {
				closes.push(id);
				return (
					options.close?.(id) ??
					({
						kind: "closed",
						cookies: ["session=; Max-Age=0"],
						session: { id, subject: "alice" },
						from: "open",
					} as const)
				);
			},
		},
		clients: { find: async () => undefined },
		sessionClients: { members: async () => [] },
		upstream:
			options.upstream === undefined
				? undefined
				: {
						name: "upstream",
						at: async (_session, back) => {
							upstreamBacks.push(back);
							return options.upstream;
						},
					},
		audit: { record: (e) => void recorded.push(e) },
		log: logged.log,
	});
	const confirm = confirmWith({
		clients: { find: async (id) => clientOf(id) },
		sessions: {
			// The browser's cookie names its session's handle directly in these tests.
			handleOf: async (request) => /session=([^;]+)/.exec(request.headers.get("cookie") ?? "")?.[1],
		},
		closing,
		keys,
		forms: {
			issue:
				options.issue ??
				(() => ({ field: "csrf_token", token: "t".repeat(43), cookies: ["csrf=t"] })),
		},
		issuer,
		confirmUrl,
		logoutUrl,
		now: () => at,
		log: logged.log,
	});
	return {
		confirm,
		closes,
		recorded,
		returns,
		upstreamBacks,
		advance: (ms: number) => {
			at += ms;
		},
	};
}

const browser = (session: string | undefined, fields: Record<string, string | string[]> = {}) =>
	testRequest({
		method: "POST",
		path: confirmPath,
		headers: new Map(session === undefined ? [] : [["cookie", `session=${session}`]]),
		form: new Map(Object.entries(fields).map(([k, v]) => [k, typeof v === "string" ? [v] : v])),
	});
const shown = (session: string | undefined): HttpRequest =>
	testRequest({
		method: "GET",
		path: confirmPath,
		headers: new Map(session === undefined ? [] : [["cookie", `session=${session}`]]),
	});
/** The page's GET carrying `request`, as the logout sends the browser to it. */
const shownWith = (session: string | undefined, request: string): HttpRequest =>
	testRequest({
		method: "GET",
		path: confirmPath,
		headers: new Map(session === undefined ? [] : [["cookie", `session=${session}`]]),
		query: new Map([["request", [request]]]),
	});
const text = (answer: HttpResponse) => String(answer.body);

describe("the confirmation of a logout a client started without a hint", () => {
	it("writes every value into its page escaped, so none can break out of its attribute or add markup, rp-logout being the one module that writes HTML [rfc6749-10.14-b]", async () => {
		const { confirm } = serve({
			issue: () => ({ field: `f"><img src=x>`, token: `t'&<b>`, cookies: [] }),
		});
		const page = text(await confirm.show(shown("s1")));
		expect(page).toContain(`name="f&#34;&#62;&#60;img src=x&#62;" value="t&#39;&#38;&#60;b&#62;"`);
		expect(page).not.toContain("<img");
		expect(page).not.toContain("<b>");
	});

	it("asks the person whether to log out, by a form bound to the session the browser holds", async () => {
		const { confirm, closes } = serve();
		const answer = await confirm.show(shown("s1"));
		expect(answer.status).toBe(200);
		expect(answer.headers).toMatchObject({
			"cache-control": "no-store",
			"content-type": "text/html; charset=utf-8",
		});
		expect(answer.loads).toEqual({ forms: "self" });
		expect(answer.cookies).toEqual(["csrf=t"]);
		expect(text(answer)).toContain("Do you want to log out of as.example?");
		expect(text(answer)).toContain(`<form method="post" action="${confirmPath}">`);
		expect(text(answer)).toContain(`name="csrf_token" value="${"t".repeat(43)}"`);
		expect(text(answer)).not.toContain("<script");
		const confirmation = /name="confirmation" value="([^"]+)"/.exec(text(answer))?.[1] ?? "";
		const bound = await keys.verify(confirmation, "logout-confirm+jwt");
		expect(bound).toEqual({
			kind: "valid",
			claims: { iss: issuer, aud: confirmUrl, sid: "s1", exp: nowS + 300 },
		});
		expect(closes).toEqual([]);
	});

	it("says the person is not signed in where the browser holds no session, closing nothing", async () => {
		const { confirm, closes } = serve();
		for (const answer of [
			await confirm.show(shown(undefined)),
			await confirm.take(browser(undefined, { confirmation: valid("s1") })),
		]) {
			expect(answer.status).toBe(200);
			expect(text(answer)).toContain("You are not signed in.");
			expect(text(answer)).not.toContain("<form");
		}
		expect(closes).toEqual([]);
	});

	it("closes the session the confirmation is bound to once agreed, and says the person is logged out", async () => {
		const { confirm, closes, recorded } = serve();
		const answer = await confirm.take(browser("s1", { confirmation: valid("s1") }));
		expect(closes).toEqual(["s1"]);
		expect([answer.status, answer.cookies]).toEqual([200, ["session=; Max-Age=0"]]);
		expect(text(answer)).toContain("You are logged out.");
		expect(answer.loads).toEqual({ frames: [], scripts: [] });
		expect(recorded.map((e) => e.kind)).toEqual(["logout.success"]);
	});

	it("moves on to the upstream's end of session by the page's script, never by a redirect after the form", async () => {
		const { confirm } = serve({ upstream: "https://idp.example/end" });
		const answer = await confirm.take(browser("s1", { confirmation: valid("s1") }));
		expect(answer.status).toBe(200);
		expect(answer.headers?.location).toBeUndefined();
		expect(text(answer)).toContain('data-target="https://idp.example/end"');
		expect(answer.loads?.scripts).toHaveLength(1);
	});

	it("asks again, closing nothing, where the browser now holds another session than the page was shown for", async () => {
		const { confirm, closes } = serve();
		const answer = await confirm.take(browser("s2", { confirmation: valid("s1") }));
		expect(closes).toEqual([]);
		expect(text(answer)).toContain("Do you want to log out");
		const again = /name="confirmation" value="([^"]+)"/.exec(text(answer))?.[1] ?? "";
		expect(await keys.verify(again, "logout-confirm+jwt")).toMatchObject({
			claims: { sid: "s2" },
		});
	});

	it("asks again for a confirmation that is missing, of another kind, or whose claims do not hold", async () => {
		const { confirm, closes } = serve();
		const wrong = {
			"no confirmation": undefined,
			"another kind": signed(
				{ iss: issuer, aud: confirmUrl, sid: "s1", exp: nowS + 300 },
				"logout+jwt",
			),
			"another issuer": valid("s1", { iss: "https://other.example" }),
			"another audience": valid("s1", { aud: `${issuer}/oauth/logout` }),
			"no sid": valid("s1", { sid: undefined }),
			"an empty sid": valid("s1", { sid: "" }),
			"no exp": valid("s1", { exp: undefined }),
			"an exp not a number": valid("s1", { exp: String(nowS + 300) }),
			"an exp at the time": valid("s1", { exp: nowS }),
		};
		for (const [name, confirmation] of Object.entries(wrong)) {
			const answer = await confirm.take(
				browser("s1", confirmation === undefined ? {} : { confirmation }),
			);
			expect([name, text(answer).includes("Do you want to log out")]).toEqual([name, true]);
		}
		expect(closes).toEqual([]);
		// A second before its end still holds.
		await confirm.take(browser("s1", { confirmation: valid("s1", { exp: nowS + 1 }) }));
		expect(closes).toEqual(["s1"]);
	});

	it("says logged out, recording nothing, for a session closed before or gone", async () => {
		const { confirm, recorded } = serve({
			close: async () => ({ kind: "closed", cookies: ["session=; Max-Age=0"] }),
		});
		const answer = await confirm.take(browser("s1", { confirmation: valid("s1") }));
		expect([answer.status, text(answer).includes("You are logged out.")]).toEqual([200, true]);
		expect(recorded).toEqual([]);
	});

	it("answers 503 for a close left pending or one that cannot be made, and for a session it cannot tell", async () => {
		const pending = serve({
			close: async (id) => ({
				kind: "pending",
				cookies: ["session=; Max-Age=0"],
				session: { id, subject: "alice" },
				from: "open",
			}),
		});
		const down = serve({
			close: async () => {
				throw new Unavailable("session");
			},
		});
		for (const { confirm } of [pending, down]) {
			const answer = await confirm.take(browser("s1", { confirmation: valid("s1") }));
			expect(answer.status).toBe(503);
		}
	});

	it("refuses a confirmation sending a field twice", async () => {
		const { confirm, closes } = serve();
		const answer = await confirm.take(browser("s1", { confirmation: [valid("s1"), valid("s1")] }));
		expect(answer.status).toBe(400);
		expect(closes).toEqual([]);
	});
});

describe("a request the logout carries", () => {
	const back = { postLogoutRedirectUri: "https://app.example/after", state: "s 1" };
	const carriedOf = (claims: Record<string, unknown>) => signed(claims, "logout-request+jwt");

	it("is signed as its own kind for the logout endpoint, with the session, client, return and state, and read back only as signed", async () => {
		const { confirm } = serve();
		const token = await confirm.carry({ sid: "s9", client: "app", back });
		expect(await keys.verify(token, "logout-request+jwt")).toEqual({
			kind: "valid",
			claims: {
				iss: issuer,
				aud: logoutUrl,
				exp: nowS + 300,
				sid: "s9",
				client: "app",
				back: back.postLogoutRedirectUri,
				state: "s 1",
			},
		});
		expect(await confirm.carried(token)).toEqual({ sid: "s9", client: "app", back });
		const held = { iss: issuer, aud: logoutUrl, exp: nowS + 300, sid: "s9" };
		const refused: Record<string, string> = {
			"a confirmation": signed(held),
			"the confirmation's audience": carriedOf({ ...held, aud: confirmUrl }),
			"another issuer": carriedOf({ ...held, iss: "https://other.example" }),
			"at its exp": carriedOf({ ...held, exp: nowS }),
			"no session": carriedOf({ ...held, sid: "" }),
			"not signed": "not-a-token",
		};
		for (const [name, token] of Object.entries(refused)) {
			expect(await confirm.carried(token), name).toBeUndefined();
		}
	});

	it("brings its return to the page, moving on to it with its state once the person agrees, closing the browser's session and never the one it names [oidc-rpinit-2-n]", async () => {
		const { confirm, closes } = serve();
		const token = await confirm.carry({ sid: "s9", client: "app", back });
		const page = text(await confirm.show(shownWith("s1", token)));
		const confirmation = /name="confirmation" value="([^"]+)"/.exec(page)?.[1] ?? "";
		const answer = await confirm.take(browser("s1", { confirmation }));
		expect(closes).toEqual(["s1"]);
		expect(answer.headers?.location).toBeUndefined();
		expect(text(answer)).toContain('data-target="https://app.example/after?state=s+1"');
	});

	it("moves on to its return from the page saying the person is not signed in, where the browser holds no session", async () => {
		const { confirm, closes } = serve();
		const token = await confirm.carry({ sid: "s9", client: "app", back });
		const answer = await confirm.show(shownWith(undefined, token));
		expect(text(answer)).toContain("You are not signed in.");
		expect(text(answer)).toContain('data-target="https://app.example/after?state=s+1"');
		expect(closes).toEqual([]);
	});

	it("asks without a return where the request does not read as one it signed", async () => {
		const { confirm } = serve();
		const page = text(await confirm.show(shownWith("s1", carriedOf({ sid: "s9", back: "x" }))));
		const confirmation = /name="confirmation" value="([^"]+)"/.exec(page)?.[1] ?? "";
		const answer = await confirm.take(browser("s1", { confirmation }));
		expect(text(answer)).toContain("You are logged out.");
		expect(text(answer)).not.toContain("data-target");
	});

	it("goes back to no return the client no longer registers, or whose client is gone, on the page without a session and after the close alike", async () => {
		const changes: Record<string, (returns: Map<string, string[]>) => void> = {
			"the return unregistered": (returns) => returns.set("app", ["https://app.example/other"]),
			"the client gone": (returns) => returns.delete("app"),
		};
		for (const [name, change] of Object.entries(changes)) {
			const { confirm, closes, returns } = serve();
			const token = await confirm.carry({ sid: "s9", client: "app", back });
			const page = text(await confirm.show(shownWith("s1", token)));
			const confirmation = /name="confirmation" value="([^"]+)"/.exec(page)?.[1] ?? "";
			change(returns);
			const alone = text(await confirm.show(shownWith(undefined, token)));
			const taken = text(await confirm.take(browser("s1", { confirmation })));
			expect([name, alone.includes("data-target"), taken.includes("data-target")]).toEqual([
				name,
				false,
				false,
			]);
			expect([name, taken.includes("You are logged out."), closes]).toEqual([name, true, ["s1"]]);
		}
	});

	it("keeps the client in the confirmation, and its time no longer than the carried request's, however late the page is shown", async () => {
		const { confirm, advance } = serve();
		const token = await confirm.carry({ sid: "s9", client: "app", back });
		advance(120_000);
		const page = text(await confirm.show(shownWith("s1", token)));
		const confirmation = /name="confirmation" value="([^"]+)"/.exec(page)?.[1] ?? "";
		expect(await keys.verify(confirmation, "logout-confirm+jwt")).toEqual({
			kind: "valid",
			claims: {
				iss: issuer,
				aud: confirmUrl,
				sid: "s1",
				exp: nowS + 300,
				client: "app",
				back: back.postLogoutRedirectUri,
				state: "s 1",
			},
		});
	});

	it("hands the upstream's end of session the return only while its client still registers it", async () => {
		for (const [name, registered] of [
			["registered", true],
			["unregistered since", false],
		] as const) {
			const { confirm, returns, upstreamBacks } = serve({ upstream: "https://idp.example/end" });
			const token = await confirm.carry({ sid: "s9", client: "app", back });
			const page = text(await confirm.show(shownWith("s1", token)));
			const confirmation = /name="confirmation" value="([^"]+)"/.exec(page)?.[1] ?? "";
			if (!registered) returns.set("app", ["https://app.example/other"]);
			await confirm.take(browser("s1", { confirmation }));
			expect([name, upstreamBacks]).toEqual([name, [registered ? back : {}]]);
		}
	});
});
