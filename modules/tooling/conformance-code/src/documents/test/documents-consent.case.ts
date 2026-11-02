import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type AreaScene, area, areaTarget, onNew, type Started } from "@mod/conformance";
import { selfSigned, startFront } from "@mod/conformance-front";
import { onLegacy } from "@mod/conformance-legacy";
import { startTunnel } from "@mod/conformance-tunnel";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../../main.ts";
import { backChannel, browserAt, succeeded } from "../../testing.ts";

// The documents' host as the app reaches it: its outbound proxy, a tunnel to a front on this machine,
// under a certificate the app is given to trust. A refusal is not remembered here, so a document that
// comes back counts at once; the scene's own value, not the default.
const host = "docs.example";
const tunnelArea = area<{ readonly proxy: string }>("documents-tunnel");
onNew(tunnelArea, (part) => ({
	config: {
		outbound: { proxy: part.proxy, allow: [host] },
		"clients-cimd": { "refused-lifetime": "0s" },
	},
}));
onLegacy(tunnelArea, { map: () => ({}), cannot: ["outbound-proxy"] });

const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const registeredId = "registered-app";
const pair = generateKeyPairSync("ed25519");
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const user = { username: "alice", password: "correct horse battery" };

/** What the front answers, by path; a path holding nothing answers 404. Nothing is kept by the app. */
const served = new Map<string, Readonly<Record<string, unknown>>>();
let paths = 0;
/** A client of its own for a scene: its id, and its document set and changed by what `more` adds. */
const documentClient = (more: Readonly<Record<string, unknown>> = {}) => {
	const path = `/client-${++paths}.json`;
	const id = `https://${host}${path}`;
	const written = (fields: Readonly<Record<string, unknown>>) =>
		served.set(path, {
			client_id: id,
			client_name: "Docs",
			redirect_uris: [callback],
			...more,
			...fields,
		});
	written({});
	return {
		id,
		path,
		change: (fields: Readonly<Record<string, unknown>>) => written(fields),
		remove: () => served.delete(path),
	};
};

const sceneOf = (proxy: string): AreaScene => {
	const scene = codeScene({
		issuer,
		keys: {
			signing: {
				kid: "dc",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		clients: [
			{
				id: registeredId,
				kind: "public",
				method: "none",
				grants: ["authorization_code"],
				scopes: ["openid", "profile"],
				redirectUris: [
					callback,
					"https://bücher.example:8443/cb",
					"http://127.0.0.1:8080/cb",
					"com.example.app://authority.example/cb",
				],
			},
		],
		users: [{ ...user, identifier: user.username, subject: "s-alice", email: "alice@example.com" }],
		discovery: true,
		userinfo: true,
		refresh: {},
		documents: { allow: [host], scopes: ["openid", "profile", "email"] },
	});
	return { ...scene, parts: { ...scene.parts, [tunnelArea.name]: { proxy } } };
};

describe.runIf(areaTarget().can("outbound-proxy"))(
	"metadata document clients: what a consent is agreed under",
	() => {
		let running: Started;
		let base = "";
		let stopHost = async () => {};
		const browser = browserAt(() => base, issuer, user);

		beforeAll(async () => {
			const dir = await mkdtemp(join(tmpdir(), "documents-consent-"));
			const tls = await selfSigned(host, dir);
			const trusted = join(dir, "trusted.pem");
			await writeFile(trusted, tls.cert);
			const front = await startFront({
				// The front answers every request itself: nothing goes on.
				upstream: () => "http://127.0.0.1:1",
				publicHost: host,
				listen: "127.0.0.1",
				tls,
				handle: (request) => {
					const document = served.get(request.url.pathname);
					return document
						? {
								status: 200,
								// Nothing is kept, so a change counts at the next request.
								headers: { "content-type": "application/json", "cache-control": "no-store" },
								body: JSON.stringify(document),
							}
						: { status: 404 };
				},
			});
			const tunnel = await startTunnel({
				allow: { [`${host}:443`]: `127.0.0.1:${new URL(front.origin).port}` },
			});
			stopHost = async () => {
				await tunnel.stop();
				await front.stop();
				await rm(dir, { recursive: true, force: true });
			};
			running = await areaTarget().start(sceneOf(`http://127.0.0.1:${tunnel.port}`), {
				trustedCertificates: [trusted],
			});
			if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
			base = running.baseUrl;
		});
		afterAll(async () => {
			if (running?.kind === "running") await running.stop();
			await stopHost();
		});

		const authorizing = (clientId: string, more: Readonly<Record<string, string>> = {}) =>
			browser.authorize({
				response_type: "code",
				client_id: clientId,
				redirect_uri: callback,
				state: "s1",
				scope: "openid",
				code_challenge: challenge,
				code_challenge_method: "S256",
				...more,
			});
		type Answered = Awaited<ReturnType<typeof authorizing>>;
		/** The challenge an answer sends the browser to the consent page with; none where it goes elsewhere. */
		const askedIn = (res: Answered) =>
			res.at?.pathname === "/consent" ? (res.at.searchParams.get("challenge") ?? "") : undefined;
		const page = async (asked: string) => {
			const res = await fetch(`${base}/oauth/consent?challenge=${asked}`, {
				headers: browser.headers({ cookie: await browser.login() }),
			});
			return { status: res.status, body: (await res.json()) as Record<string, unknown> };
		};
		/** Accepts on the page and follows the browser back to the endpoint, answering where that sends it. */
		const accepted = async (asked: string) => {
			const cookie = await browser.login();
			const res = await fetch(`${base}/oauth/consent`, {
				method: "POST",
				redirect: "manual",
				headers: browser.headers({
					cookie,
					origin: issuer,
					"content-type": "application/x-www-form-urlencoded",
				}),
				body: new URLSearchParams({ challenge: asked, decision: "accept" }),
			});
			expect(res.status).toBe(303);
			const back = new URL(res.headers.get("location") ?? "");
			const again = await fetch(`${base}${back.pathname}${back.search}`, {
				redirect: "manual",
				headers: browser.headers({ cookie }),
			});
			return new URL(again.headers.get("location") ?? "", issuer);
		};
		/** A request carried through the consent page, answering where it ends. */
		const agreed = async (clientId: string, more: Readonly<Record<string, string>> = {}) => {
			const asked = askedIn(await authorizing(clientId, more));
			expect(asked, "the consent page is asked").toBeDefined();
			return accepted(asked ?? "");
		};
		const codeIn = (at: URL | undefined) => at?.searchParams.get("code") ?? null;
		const tokensFrom = async (clientId: string, at: URL) => {
			const res = await fetch(`${base}/oauth/token`, {
				method: "POST",
				headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					grant_type: "authorization_code",
					client_id: clientId,
					code: codeIn(at) ?? "",
					redirect_uri: callback,
					code_verifier: verifier,
				}),
			});
			return (await succeeded(res, "the token endpoint")) as Record<string, string>;
		};
		const userinfoOf = async (accessToken: string | undefined) => {
			const res = await fetch(`${base}/oauth/userinfo`, {
				headers: { ...backChannel, authorization: `Bearer ${accessToken}` },
			});
			return succeeded(res, "userinfo");
		};

		describe("the consent page's redirect hosts", () => {
			it("names each of a client's destinations for a client the operator registered, a host as the parser writes it, and a private-use scheme's authority never as a host", async () => {
				const asked = askedIn(await authorizing(registeredId));
				const shown = await page(asked ?? "");
				expect(shown.body.redirect_hosts).toEqual([
					{ host: "app.example", kind: "web" },
					{ host: "xn--bcher-kva.example:8443", kind: "web" },
					{ host: "127.0.0.1", kind: "loopback" },
					{ host: "com.example.app", kind: "app" },
				]);
			});

			it("names them for a client from a document too", async () => {
				const client = documentClient({
					redirect_uris: [callback, "http://localhost:3000/cb"],
				});
				const shown = await page(askedIn(await authorizing(client.id)) ?? "");
				expect(shown.body.redirect_hosts).toEqual([
					{ host: "app.example", kind: "web" },
					{ host: "localhost:3000", kind: "loopback" },
				]);
			});
		});

		describe("a document that changes after the consent", () => {
			it("asks again for a document naming another redirect URI, with no code in any answer, and refuses a silent request", async () => {
				const client = documentClient();
				expect(codeIn(await agreed(client.id))).not.toBeNull();
				expect(codeIn((await authorizing(client.id)).at)).not.toBeNull();
				const added = "https://redirect.example/cb";
				client.change({ redirect_uris: [callback, added] });

				const atAdded = await authorizing(client.id, { redirect_uri: added });
				expect(atAdded.at?.pathname).toBe("/consent");
				expect(codeIn(atAdded.at)).toBeNull();
				const atOld = await authorizing(client.id);
				expect(atOld.at?.pathname).toBe("/consent");
				expect(codeIn(atOld.at)).toBeNull();

				const silent = await authorizing(client.id, { redirect_uri: added, prompt: "none" });
				expect(silent.at?.host).toBe("redirect.example");
				expect(silent.at?.searchParams.get("error")).toBe("consent_required");
				expect(codeIn(silent.at)).toBeNull();
			});

			it("asks again when a field the provider does not read changes", async () => {
				const client = documentClient();
				await agreed(client.id);
				client.change({ tos_uri: "https://app.example/terms" });
				expect(askedIn(await authorizing(client.id))).toBeDefined();
			});

			it("asks again when a document comes to name the refresh grant", async () => {
				const client = documentClient();
				await agreed(client.id);
				client.change({ grant_types: ["authorization_code", "refresh_token"] });
				expect(askedIn(await authorizing(client.id))).toBeDefined();
			});

			it("carries no scope agreed to under the document before into the next agreement", async () => {
				const client = documentClient();
				await agreed(client.id, { scope: "openid profile" });
				client.change({ client_name: "Docs, again" });
				const asked = askedIn(await authorizing(client.id));
				expect((await page(asked ?? "")).body.granted_scopes).toEqual([]);
				expect(codeIn(await accepted(asked ?? ""))).not.toBeNull();
				// Agreed to now for openid alone: what it agreed to before the change stays out.
				expect(codeIn((await authorizing(client.id)).at)).not.toBeNull();
				const wider = await authorizing(client.id, { scope: "openid profile" });
				expect(wider.at?.pathname).toBe("/consent");
				expect((await page(askedIn(wider) ?? "")).body.granted_scopes).toEqual(["openid"]);
			});

			it("knows no challenge made before the document changed, and asks again after an answer to one", async () => {
				const client = documentClient();
				const asked = askedIn(await authorizing(client.id)) ?? "";
				expect((await page(asked)).status).toBe(200);
				client.change({ client_name: "Docs, again" });
				expect(await page(asked)).toEqual({
					status: 400,
					body: { error: "unknown_challenge" },
				});
				// An answer agrees to what was shown, so the changed document is asked of again.
				expect((await accepted(asked)).pathname).toBe("/consent");
			});

			it("asks nothing again for a document gone and back unchanged, and asks when it comes back changed", async () => {
				const client = documentClient();
				await agreed(client.id);
				client.remove();
				expect((await authorizing(client.id)).status).toBe(400);
				client.change({});
				expect(codeIn((await authorizing(client.id)).at)).not.toBeNull();
				client.remove();
				expect((await authorizing(client.id)).status).toBe(400);
				client.change({ client_name: "Docs, again" });
				expect(askedIn(await authorizing(client.id))).toBeDefined();
			});

			it("asks of the same content at another URL, which is another client", async () => {
				const client = documentClient();
				await agreed(client.id);
				const other = documentClient();
				expect(askedIn(await authorizing(other.id))).toBeDefined();
			});

			it("asks a registered client's user once, as nothing a source reads stands behind it", async () => {
				expect(codeIn(await agreed(registeredId))).not.toBeNull();
				expect(codeIn((await authorizing(registeredId)).at)).not.toBeNull();
				expect(codeIn((await authorizing(registeredId, { prompt: "none" })).at)).not.toBeNull();
			});
		});

		describe("a claim asked by name", () => {
			const emailAtUserinfo = { claims: JSON.stringify({ userinfo: { email: null } }) };

			it("is cut from a new code, and from a refreshed token, once the document changes", async () => {
				const client = documentClient({ grant_types: ["authorization_code", "refresh_token"] });
				// Agreed to under this document: email, by the scope, then asked by its name alone.
				await agreed(client.id, { scope: "openid email" });
				const named = await authorizing(client.id, emailAtUserinfo);
				const tokens = await tokensFrom(client.id, named.at as URL);
				expect(await userinfoOf(tokens.access_token)).toMatchObject({
					email: "alice@example.com",
				});

				client.change({ client_name: "Docs, again" });
				const refreshed = await fetch(`${base}/oauth/token`, {
					method: "POST",
					headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
					body: new URLSearchParams({
						grant_type: "refresh_token",
						client_id: client.id,
						refresh_token: tokens.refresh_token ?? "",
					}),
				});
				const again = (await succeeded(refreshed, "the token endpoint")) as Record<string, string>;
				expect(await userinfoOf(again.access_token)).not.toHaveProperty("email");

				const at = await agreed(client.id, emailAtUserinfo);
				const fresh = await tokensFrom(client.id, at);
				expect(await userinfoOf(fresh.access_token)).not.toHaveProperty("email");
			});
		});

		describe("a document's redirect URIs", () => {
			it("refuses a document whose https redirect URI lacks the two slashes", async () => {
				for (const uri of ["https:redirect.example/cb", "https:/redirect.example/cb"]) {
					const client = documentClient({ redirect_uris: [uri] });
					const res = await authorizing(client.id, { redirect_uri: uri });
					expect([uri, res.status, res.at]).toEqual([uri, 400, undefined]);
				}
			});
		});
	},
);
