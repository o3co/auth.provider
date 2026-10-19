import { createHash, generateKeyPairSync } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { areaTarget, fakeHttp, type Started, sceneOf } from "@mod/conformance";
import { codeArea } from "@mod/conformance-code";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import type { ClientScene } from "@mod/conformance-oauth";
import { oauthArea } from "@mod/conformance-oauth";
import { totp } from "@mod/conformance-second-factor/testing";
import { usersLedger } from "@mod/users-http/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	commands,
	composedBy,
	recipesArea,
	shownCommand,
	transcript,
	withBlocks,
} from "../src/main.ts";

const workspace = join(import.meta.dirname, "..", "..", "..", "..");
const recipe = join(workspace, "docs", "recipe-mfa-page.md");
const issuer = "https://auth.example";
const callback = "https://app.example/callback";
const password = "correct horse battery";
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const pair = generateKeyPairSync("ed25519");
const app: ClientScene = {
	id: "my-web-app",
	kind: "confidential",
	method: "client_secret_post",
	secret: "my-web-app-secret-0123456789abcdef",
	grants: ["authorization_code"],
	scopes: ["openid"],
	defaultScopes: ["openid"],
	redirectUris: [callback],
	firstParty: true,
};
const authorize = `${issuer}/oauth/authorize?${new URLSearchParams({
	response_type: "code",
	client_id: app.id,
	redirect_uri: callback,
	scope: "openid",
	state: "xyz",
	code_challenge: challenge,
	code_challenge_method: "S256",
})}`;

describe("the recipe for a login page with a second factor", () => {
	let fake: Awaited<ReturnType<typeof fakeHttp>> | undefined;
	let started: Extract<Started, { kind: "running" }> | undefined;

	beforeAll(async () => {
		const ledger = usersLedger([{ identifier: "alice", password, subject: "u-alice" }]);
		fake = await fakeHttp((asked) => ledger.answer(asked) ?? { status: 404 });
		const section = ledger.section(fake.base)["users-http"];
		const modules = await composedBy(commands["mfa-page"], workspace);
		const running = await areaTarget().start(
			sceneOf(
				keysArea.part({
					signing: {
						kid: "recipe",
						alg: "EdDSA",
						privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
						publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
					},
				}),
				identityArea.part({
					origin: issuer,
					users: [],
					ledger: {
						verifyUrl: section["verify-url"],
						credential: section.credential,
					},
				}),
				oauthArea.part({ issuer, clients: [app] }),
				codeArea.part({ withoutConsent: true }),
				recipesArea.part({ modules }),
			),
		);
		if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
		started = running;
	});
	afterAll(async () => {
		await started?.stop();
		await fake?.stop();
	});

	it("binds TOTP at a first login, lets the next login in with it, and shows each step as the recipe does", async () => {
		const base = started?.baseUrl ?? "";
		const t = transcript(base, issuer);
		t.mask("expires_in", "<seconds>");
		t.name(password, "<password>");
		const jar = new Map<string, string>();
		/** A browser behind the deployment's proxy: cookies kept, and the proxy's headers, neither shown. */
		const send = async (
			method: "GET" | "POST",
			path: string,
			json?: Record<string, unknown>,
			shown: Record<string, string> = {},
		) => {
			const answer = await t.send(method, path.replace(issuer, ""), {
				headers: {
					"x-forwarded-proto": "https",
					"x-forwarded-for": "198.51.100.30",
					"x-forwarded-host": new URL(issuer).host,
					origin: issuer,
					cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; "),
					...(json ? { "content-type": "application/json" } : {}),
					...shown,
				},
				...(json ? { body: JSON.stringify(json) } : {}),
			});
			for (const c of answer.headers.getSetCookie()) {
				const [first = ""] = c.split(";");
				const at = first.indexOf("=");
				if (first.slice(at + 1)) jar.set(first.slice(0, at), first.slice(at + 1));
				else jar.delete(first.slice(0, at));
			}
			return {
				...answer,
				body: (answer.text ? JSON.parse(answer.text) : {}) as Record<string, unknown>,
			};
		};

		t.block("first-login");
		const sent = await send("GET", authorize);
		expect(sent.status, "the authorization endpoint sends the browser to log in").toBe(302);
		const csrf = String((await send("GET", "/session/csrf")).body.csrf_token);
		t.name(csrf, "<csrf_token>");
		const login = () =>
			send(
				"POST",
				"/session/login",
				{ username: "alice", password, redirect_to: authorize },
				{ "x-csrf-token": csrf },
			);
		const first = await login();
		expect([first.status, first.body.error]).toEqual([403, "mfa_enrollment_required"]);
		const binding = String(first.body.transaction);
		t.name(binding, "<transaction>");

		t.block("enroll");
		const begun = await send(
			"POST",
			"/session/mfa/enrollment",
			{ kind: "totp", transaction_id: binding },
			{ "x-csrf-token": csrf },
		);
		expect(begun.status).toBe(200);
		const secret = String(begun.body.secret);
		t.name(secret, "<secret>");
		const enrolCode = totp(secret);
		t.name(enrolCode, "<totp_code>");
		const bound = await send(
			"POST",
			"/session/mfa/enrollment/complete",
			{ transaction_id: binding, proof: enrolCode },
			{ "x-csrf-token": csrf },
		);
		expect(bound.status).toBe(200);
		t.name(String((bound.body.factor as { id?: string } | undefined)?.id ?? ""), "<factor_id>");

		t.block("second-login");
		const second = await login();
		expect([second.status, second.body.error]).toEqual([403, "mfa_required"]);
		const proving = String(second.body.transaction);
		t.name(proving, "<transaction>");

		t.block("factors");
		const listed = await send("GET", "/session/mfa/transaction", undefined, {
			"mfa-transaction": proving,
		});
		const factor = (listed.body.factors as { id: string; kind: string }[]).find(
			(f) => f.kind === "totp",
		);
		expect(factor).toBeDefined();
		t.name(factor?.id ?? "", "<factor_id>");

		t.block("verify");
		const code = totp(secret, 1);
		t.name(code, "<totp_code>");
		const verified = await send(
			"POST",
			"/session/mfa/verify",
			{ transaction_id: proving, factor_id: factor?.id, proof: code },
			{ "x-csrf-token": csrf },
		);
		expect(verified.status).toBe(200);
		const back = String(verified.body.redirect_to);
		expect(back.startsWith(`${issuer}/oauth/authorize`)).toBe(true);

		t.block("continue");
		const onward = await send("GET", back);
		const to = new URL(onward.headers.get("location") ?? "", issuer);
		expect([to.origin + to.pathname, to.searchParams.get("state")]).toEqual([callback, "xyz"]);
		t.name(to.searchParams.get("code") ?? "", "<code>");

		const blocks = {
			command: ["```sh", shownCommand(commands["mfa-page"]), "```"].join("\n"),
			...Object.fromEntries(
				["first-login", "enroll", "second-login", "factors", "verify", "continue"].map((name) => [
					name,
					t.text(name),
				]),
			),
		};
		const committed = readFileSync(recipe, "utf8");
		const generated = withBlocks(committed, blocks);
		if (process.env.RECIPES_WRITE) writeFileSync(recipe, generated);
		else {
			expect(
				committed,
				"the recipe's blocks are generated: run `pnpm --filter @mod/conformance-recipes run examples`",
			).toBe(generated);
		}
	});
});
