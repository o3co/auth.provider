import type { AuditRecord } from "@mod/audit";
import type { HttpRequest, HttpResponse } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import type { CloseOutcome } from "@mod/session";
import { describe, expect, it } from "vitest";
import { confirmOver, confirmPath } from "../confirm.ts";

const issuer = "https://as.example";
const confirmUrl = `${issuer}${confirmPath}`;
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
	} = {},
) {
	const closes: string[] = [];
	const recorded: AuditRecord[] = [];
	const logged = recordingLog();
	const confirm = confirmOver({
		sessions: {
			// The browser's cookie names its session's handle directly in these tests.
			handleOf: async (request) => /session=([^;]+)/.exec(request.headers.get("cookie") ?? "")?.[1],
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
		keys,
		forms: {
			issue: () => ({ field: "csrf_token", token: "t".repeat(43), cookies: ["csrf=t"] }),
		},
		clients: { find: async () => undefined },
		sessionClients: { members: async () => [] },
		upstream:
			options.upstream === undefined
				? undefined
				: { name: "upstream", at: async () => options.upstream },
		audit: { record: (e) => void recorded.push(e) },
		issuer,
		confirmUrl,
		now: () => nowMs,
		log: logged.log,
	});
	return { confirm, closes, recorded };
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
const text = (answer: HttpResponse) => String(answer.body);

describe("the confirmation of a logout a client started without a hint", () => {
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
