import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { areaTarget, type Started, sceneOf } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	commands,
	composedBy,
	recipesArea,
	scripts,
	shownCommand,
	shownScript,
	transcript,
	withBlocks,
} from "../src/main.ts";

const workspace = join(import.meta.dirname, "..", "..", "..", "..");
const recipe = join(workspace, "docs", "recipe-first-login.md");
const origin = "http://127.0.0.1:8080";
const callback = "http://localhost:3000/callback";
const password = "correct horse battery";
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const authorize = `${origin}/oauth/authorize?${new URLSearchParams({
	response_type: "code",
	client_id: "my-app",
	redirect_uri: callback,
	scope: "openid",
	state: "xyz",
	code_challenge: challenge,
	code_challenge_method: "S256",
})}`;

/** Runs a script as its reader does, with `input` on standard input. */
const ran = (script: string, input?: string) =>
	execFileSync(process.execPath, ["-e", script], input === undefined ? {} : { input })
		.toString()
		.trim();

/** The reader's `config/local.conf`, with the key and the hash their scripts printed. */
const localConf = (pem: string, hash: string) => `kernel.deployment = single
kernel.environment = development
issuer.url = "${origin}"
http {
  public-origin = "${origin}"
  insecure-origin = true
}
authorize.login-page = "${origin}/login"
tokens.revocation = denylist
store.accept-volatile = true
audit.receivers = [log]
keys.signing {
  kid = signing-1
  alg = RS256
  private-key = """${pem}"""
}
users.registered = [
  { identifier = alice, password-hash = "${hash}" }
]
clients.registered = [
  {
    id = my-app
    kind = public
    method = none
    sections {
      client-allowance { grants = [authorization_code], scopes = [openid], default-scopes = [openid], audiences = [] }
      authorize { redirect-uris = ["${callback}"] }
      consent { first-party = true }
    }
  }
]
`;

describe("the recipe for a first login", () => {
	let started: Extract<Started, { kind: "running" }> | undefined;
	let pem = "";
	let hash = "";
	let conf = "";

	beforeAll(async () => {
		pem = ran(scripts["signing-key"]);
		hash = ran(scripts["password-hash"], `${password}\n`);
		conf = localConf(pem, hash);
		const modules = await composedBy(commands["first-login"], workspace);
		const running = await areaTarget().start(
			sceneOf(recipesArea.part({ modules, localConf: conf })),
		);
		if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
		started = running;
	});
	afterAll(async () => {
		await started?.stop();
	});

	it("logs a configured user in with the key and hash its scripts make, and shows each step as the recipe does [rfc6749-4.1.2-a] [rfc6749-4.1.2-f] [oidc-core-3.1.2.5-a] [rfc7636-4.6-a]", async () => {
		const base = started?.baseUrl ?? "";
		const t = transcript(base, origin);
		t.name(password, "<password>");
		for (const key of ["access_token", "id_token"]) t.mask(key, `<${key}>`);
		t.mask("expires_in", "<seconds>");
		const jar = new Map<string, string>();
		/** A browser at the deployment's origin: cookies kept and not shown. */
		const send = async (
			method: "GET" | "POST",
			path: string,
			init: {
				readonly json?: Record<string, unknown>;
				readonly form?: Record<string, string>;
			} = {},
			shown: Record<string, string> = {},
		) => {
			const body = init.json
				? JSON.stringify(init.json)
				: init.form
					? new URLSearchParams(init.form).toString()
					: undefined;
			const answer = await t.send(method, path.replace(origin, ""), {
				headers: {
					origin,
					cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; "),
					...(init.json ? { "content-type": "application/json" } : {}),
					...(init.form ? { "content-type": "application/x-www-form-urlencoded" } : {}),
					...shown,
				},
				...(body === undefined ? {} : { body }),
			});
			for (const c of answer.headers.getSetCookie()) {
				const [first = ""] = c.split(";");
				const at = first.indexOf("=");
				if (first.slice(at + 1)) jar.set(first.slice(0, at), first.slice(at + 1));
				else jar.delete(first.slice(0, at));
			}
			return {
				...answer,
				body: (answer.text.startsWith("{") ? JSON.parse(answer.text) : {}) as Record<
					string,
					unknown
				>,
			};
		};

		t.block("login");
		const sent = await send("GET", authorize);
		expect(sent.status, "the authorization endpoint sends the browser to log in").toBe(302);
		const csrf = String((await send("GET", "/session/csrf")).body.csrf_token);
		t.name(csrf, "<csrf_token>");
		const login = await send(
			"POST",
			"/session/login",
			{ json: { username: "alice", password, redirect_to: authorize } },
			{ "x-csrf-token": csrf },
		);
		expect(login.status, login.text).toBe(200);
		const back = String(login.body.redirect_to);
		expect(back.startsWith(`${origin}/oauth/authorize`)).toBe(true);
		const onward = await send("GET", back);
		const to = new URL(onward.headers.get("location") ?? "", origin);
		expect([to.origin + to.pathname, to.searchParams.get("state")]).toEqual([callback, "xyz"]);
		const code = to.searchParams.get("code") ?? "";
		expect(code, to.search).not.toBe("");
		t.name(code, "<code>");

		t.block("token");
		const token = await send("POST", "/oauth/token", {
			form: {
				grant_type: "authorization_code",
				code,
				redirect_uri: callback,
				client_id: "my-app",
				code_verifier: verifier,
			},
		});
		expect(token.status, token.text).toBe(200);
		expect(token.body.token_type).toBe("Bearer");

		const shownConf = conf
			.replace(
				pem,
				"-----BEGIN PRIVATE KEY-----\n<the key the script printed>\n-----END PRIVATE KEY-----",
			)
			.replace(hash, "<the hash the script printed>");
		const blocks = {
			command: ["```sh", shownCommand(commands["first-login"]), "```"].join("\n"),
			"signing-key": ["```sh", shownScript(scripts["signing-key"]), "```"].join("\n"),
			"password-hash": ["```sh", shownScript(scripts["password-hash"]), "```"].join("\n"),
			"local-conf": ["```hocon", shownConf.trimEnd(), "```"].join("\n"),
			login: t.text("login"),
			token: t.text("token"),
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
