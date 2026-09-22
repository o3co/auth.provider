/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { delay, HttpResponse, http } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
	DEFAULT_MAX_RESPONSE_BYTES,
	type FederatedIdentityLookupCoverage,
	HttpUserRepository,
} from "../HttpUserRepository.mjs";

// Loopback, so it exercises the documented `http://` carve-out rather than
// needing a TLS fixture. See `src/endpointUrl.mts`.
const BASE_URL = "http://localhost:18080";

const mockUser = { id: "user-1", username: "alice" };

const handlers = [
	http.post(`${BASE_URL}/user/authenticate`, async ({ request }) => {
		const body = (await request.json()) as { email?: string; password?: string };
		if (body.email === "alice@example.com" && body.password === "correct-pass") {
			return HttpResponse.json(mockUser, { status: 200 });
		}
		return new HttpResponse(null, { status: 401 });
	}),
	http.post(`${BASE_URL}/user/authenticate/token`, async ({ request }) => {
		const body = (await request.json()) as { token?: string };
		if (body.token === "valid-token") {
			return HttpResponse.json(mockUser, { status: 200 });
		}
		return new HttpResponse(null, { status: 401 });
	}),
];

const server = setupServer(...handlers);

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("HttpUserRepository", () => {
	const repo = new HttpUserRepository({
		authenticateUrl: `${BASE_URL}/user/authenticate`,
		authenticateByTokenUrl: `${BASE_URL}/user/authenticate/token`,
		timeout: 5000,
	});

	describe("authenticate", () => {
		it("returns user on success", async () => {
			const user = await repo.authenticate("alice@example.com", "correct-pass");
			expect(user).not.toBeNull();
			expect(user?.id).toBe("user-1");
			expect(user?.username).toBe("alice");
		});

		it("sends email field (not username) in request body", async () => {
			let capturedBody: Record<string, unknown> | null = null;
			server.use(
				http.post(`${BASE_URL}/user/authenticate`, async ({ request }) => {
					capturedBody = (await request.json()) as Record<string, unknown>;
					return HttpResponse.json(mockUser, { status: 200 });
				}),
			);
			await repo.authenticate("alice@example.com", "correct-pass");
			expect(capturedBody).not.toBeNull();
			expect(capturedBody).toHaveProperty("email", "alice@example.com");
			expect(capturedBody).not.toHaveProperty("username");
		});

		it("returns null on 401", async () => {
			const user = await repo.authenticate("alice@example.com", "wrong-pass");
			expect(user).toBeNull();
		});

		it("throws on unexpected HTTP status", async () => {
			server.use(
				http.post(`${BASE_URL}/user/authenticate`, () => {
					return new HttpResponse(null, { status: 500 });
				}),
			);
			await expect(repo.authenticate("alice@example.com", "pass")).rejects.toThrow(
				"Unexpected HTTP status 500",
			);
		});
	});

	describe("authenticateByToken", () => {
		it("returns user on success", async () => {
			const user = await repo.authenticateByToken("valid-token");
			expect(user).not.toBeNull();
			expect(user?.id).toBe("user-1");
			expect(user?.username).toBe("alice");
		});

		it("returns null on 401", async () => {
			const user = await repo.authenticateByToken("invalid-token");
			expect(user).toBeNull();
		});
	});

	// TS-2 (Wave 5g): pre-fix, `(await res.json()) as User` was a compile-time
	// cast only. A 200 response with an unexpected body shape silently
	// produced a `User` whose required fields were `undefined`, leaking
	// `sub: undefined` into the authentication flow. The new `isUser`
	// runtime guard rejects such shapes by throwing — an "upstream broken"
	// failure is distinct from "user not found" (401).
	describe("TS-2: upstream response shape validation", () => {
		it("throws when upstream 200 returns an object missing required fields", async () => {
			server.use(
				http.post(`${BASE_URL}/user/authenticate`, () => {
					return HttpResponse.json({ status: "ok" }, { status: 200 });
				}),
			);
			await expect(repo.authenticate("alice@example.com", "pass")).rejects.toThrow(
				/invalid User shape/,
			);
		});

		it("throws when upstream 200 returns non-string id", async () => {
			server.use(
				http.post(`${BASE_URL}/user/authenticate`, () => {
					return HttpResponse.json({ id: 123, username: "alice" }, { status: 200 });
				}),
			);
			await expect(repo.authenticate("alice@example.com", "pass")).rejects.toThrow(
				/invalid User shape/,
			);
		});

		it("throws when upstream 200 returns null body", async () => {
			server.use(
				http.post(`${BASE_URL}/user/authenticate`, () => {
					return HttpResponse.json(null, { status: 200 });
				}),
			);
			await expect(repo.authenticate("alice@example.com", "pass")).rejects.toThrow(
				/invalid User shape/,
			);
		});

		it("accepts valid User shape with extra fields (index-signature passthrough)", async () => {
			server.use(
				http.post(`${BASE_URL}/user/authenticate`, () => {
					return HttpResponse.json(
						{ id: "u1", username: "alice", email: "a@x", role: "admin" },
						{ status: 200 },
					);
				}),
			);
			const user = await repo.authenticate("alice@example.com", "pass");
			expect(user?.id).toBe("u1");
			expect(user?.username).toBe("alice");
			// Extra fields preserved via the `User` index signature.
			expect((user as Record<string, unknown>).email).toBe("a@x");
		});
	});

	// #285: the endpoints receive plaintext credentials. A mistyped `http://`
	// URL published them to every hop on the path and nothing refused it. The
	// check lives in the CONSTRUCTOR so a misconfigured deployment fails at
	// boot rather than at the first login attempt.
	describe("#285: endpoints must be https (loopback carve-out)", () => {
		const secure = {
			authenticateUrl: "https://users.example.com/authenticate",
			authenticateByTokenUrl: "https://users.example.com/authenticate-by-token",
			timeout: 5000,
		};

		it("rejects a plaintext authenticateUrl at construction", () => {
			expect(
				() =>
					new HttpUserRepository({
						...secure,
						authenticateUrl: "http://users.example.com/authenticate",
					}),
			).toThrow(/authenticateUrl/);
		});

		it("rejects a plaintext authenticateByTokenUrl at construction", () => {
			expect(
				() =>
					new HttpUserRepository({
						...secure,
						authenticateByTokenUrl: "http://users.example.com/authenticate-by-token",
					}),
			).toThrow(/authenticateByTokenUrl/);
		});

		it("rejects a private-range http host — internal is not a synonym for encrypted", () => {
			expect(
				() => new HttpUserRepository({ ...secure, authenticateUrl: "http://10.0.0.5/auth" }),
			).toThrow(/https/);
		});

		it("rejects a non-http(s) scheme and a bare host", () => {
			expect(
				() => new HttpUserRepository({ ...secure, authenticateUrl: "ftp://users.example.com/x" }),
			).toThrow(/authenticateUrl/);
			expect(
				() => new HttpUserRepository({ ...secure, authenticateUrl: "users.example.com:3000" }),
			).toThrow(/authenticateUrl/);
		});

		it("rejects credentials embedded in the URL", () => {
			expect(
				() =>
					new HttpUserRepository({
						...secure,
						authenticateUrl: "https://u:p@users.example.com/x",
					}),
			).toThrow(/authenticateUrl/);
		});

		it("accepts https", () => {
			expect(() => new HttpUserRepository(secure)).not.toThrow();
		});

		it("accepts http on loopback hosts so local development needs no TLS", () => {
			for (const host of [
				"localhost:18080",
				"127.0.0.1:18080",
				"127.0.0.53:18080",
				"[::1]:18080",
			]) {
				expect(
					() =>
						new HttpUserRepository({
							authenticateUrl: `http://${host}/authenticate`,
							authenticateByTokenUrl: `http://${host}/authenticate/token`,
							timeout: 5000,
						}),
				).not.toThrow();
			}
		});
	});

	// #285: `timeout` reached `setTimeout` unvalidated. `0`, a negative number
	// and `NaN` all clamp to "fire immediately", so a typo'd or blank-env
	// timeout aborted every request instead of allowing a long one.
	describe("#285: timeout validation", () => {
		const urls = {
			authenticateUrl: "https://users.example.com/authenticate",
			authenticateByTokenUrl: "https://users.example.com/authenticate-by-token",
		};

		it("rejects non-positive, non-integer and non-finite timeouts", () => {
			for (const timeout of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
				expect(() => new HttpUserRepository({ ...urls, timeout })).toThrow(/timeout/);
			}
		});

		it("rejects a timeout above the Node timer range, which setTimeout would clamp to 1ms", () => {
			expect(() => new HttpUserRepository({ ...urls, timeout: 2_147_483_648 })).toThrow(/timeout/);
		});

		it("accepts a positive integer", () => {
			expect(() => new HttpUserRepository({ ...urls, timeout: 1 })).not.toThrow();
			expect(() => new HttpUserRepository({ ...urls, timeout: 2_147_483_647 })).not.toThrow();
		});

		it("applies the timeout to a body that stalls after the headers arrive", async () => {
			// The slow-loris shape: the Store answers 200 promptly, then dribbles.
			// The deadline has to cover the body read, not just the response.
			server.use(
				http.post(`${BASE_URL}/user/authenticate`, () => {
					const stream = new ReadableStream<Uint8Array>({
						start(ctrl) {
							ctrl.enqueue(new TextEncoder().encode('{"id":"u1",'));
							// ...and never closes.
						},
					});
					return new HttpResponse(stream, {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				}),
			);
			const impatient = new HttpUserRepository({
				authenticateUrl: `${BASE_URL}/user/authenticate`,
				authenticateByTokenUrl: `${BASE_URL}/user/authenticate/token`,
				timeout: 30,
			});
			await expect(impatient.authenticate("alice@example.com", "pass")).rejects.toThrow(
				/timed out after 30ms/,
			);
		});

		it("actually applies the timeout to the request", async () => {
			server.use(
				http.post(`${BASE_URL}/user/authenticate`, async () => {
					await delay(300);
					return HttpResponse.json(mockUser, { status: 200 });
				}),
			);
			const impatient = new HttpUserRepository({
				authenticateUrl: `${BASE_URL}/user/authenticate`,
				authenticateByTokenUrl: `${BASE_URL}/user/authenticate/token`,
				timeout: 20,
			});
			await expect(impatient.authenticate("alice@example.com", "pass")).rejects.toThrow(
				/timed out after 20ms/,
			);
		});
	});

	// #285: `res.json()` buffers whatever the upstream sends. A hostile or
	// broken Store could stream gigabytes into the process.
	describe("#285: response body cap", () => {
		const capped = () =>
			new HttpUserRepository({
				authenticateUrl: `${BASE_URL}/user/authenticate`,
				authenticateByTokenUrl: `${BASE_URL}/user/authenticate/token`,
				timeout: 5000,
				maxResponseBytes: 256,
			});

		it("defaults to 1 MiB", () => {
			expect(DEFAULT_MAX_RESPONSE_BYTES).toBe(1024 * 1024);
		});

		it("rejects a maxResponseBytes that is not a positive integer", () => {
			for (const maxResponseBytes of [0, -1, 1.5, Number.NaN]) {
				expect(
					() =>
						new HttpUserRepository({
							authenticateUrl: `${BASE_URL}/user/authenticate`,
							authenticateByTokenUrl: `${BASE_URL}/user/authenticate/token`,
							timeout: 5000,
							maxResponseBytes,
						}),
				).toThrow(/maxResponseBytes/);
			}
		});

		it("still accepts a body under the cap", async () => {
			server.use(
				http.post(`${BASE_URL}/user/authenticate`, () =>
					HttpResponse.json(mockUser, { status: 200 }),
				),
			);
			const user = await capped().authenticate("alice@example.com", "pass");
			expect(user?.id).toBe("user-1");
		});

		it("refuses an oversized body declared by Content-Length", async () => {
			server.use(
				http.post(`${BASE_URL}/user/authenticate`, () =>
					HttpResponse.json(
						{ id: "u1", username: "alice", padding: "x".repeat(4096) },
						{ status: 200 },
					),
				),
			);
			await expect(capped().authenticate("alice@example.com", "pass")).rejects.toThrow(
				/exceeds the 256-byte cap/,
			);
		});

		it("refuses an oversized chunked body that declares no Content-Length", async () => {
			// The interesting case: a hostile Store simply omits Content-Length,
			// so the cap has to be enforced while reading, not from the header.
			server.use(
				http.post(`${BASE_URL}/user/authenticate`, () => {
					const chunk = new TextEncoder().encode("x".repeat(128));
					let sent = 0;
					const stream = new ReadableStream<Uint8Array>({
						pull(ctrl) {
							sent += 1;
							if (sent > 64) {
								ctrl.close();
								return;
							}
							ctrl.enqueue(chunk);
						},
					});
					return new HttpResponse(stream, {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				}),
			);
			await expect(capped().authenticate("alice@example.com", "pass")).rejects.toThrow(
				/exceeds the 256-byte cap/,
			);
		});

		it("reports an empty 200 as an upstream failure rather than a parser crash", async () => {
			// A Store that answers 200 with no body at all — `res.body` is null,
			// so there is nothing to read and nothing to parse.
			server.use(
				http.post(`${BASE_URL}/user/authenticate`, () => new HttpResponse(null, { status: 200 })),
			);
			await expect(capped().authenticate("alice@example.com", "pass")).rejects.toThrow(
				/non-JSON body/,
			);
		});

		it("reports a non-JSON body as an upstream failure rather than a parser crash", async () => {
			server.use(
				http.post(`${BASE_URL}/user/authenticate`, () => new HttpResponse("<html>502</html>")),
			);
			await expect(capped().authenticate("alice@example.com", "pass")).rejects.toThrow(
				/non-JSON body/,
			);
		});
	});

	describe("linkFederatedIdentity (#482)", () => {
		const LINK_URL = `${BASE_URL}/user/link`;
		const linking = () =>
			new HttpUserRepository({
				authenticateUrl: `${BASE_URL}/user/authenticate`,
				authenticateByTokenUrl: `${BASE_URL}/user/authenticate/token`,
				linkFederatedIdentityUrl: LINK_URL,
				timeout: 5000,
			});
		const identity = {
			provider: "apple",
			sub: "a1",
			token: "apple:a1",
			claims: { email: "a@example.com", emailVerified: true },
		};
		const answer = (status: number) =>
			server.use(http.post(LINK_URL, () => new HttpResponse(null, { status })));

		it("is absent unless linkFederatedIdentityUrl is configured", () => {
			expect(repo.linkFederatedIdentity).toBeUndefined();
			expect(typeof linking().linkFederatedIdentity).toBe("function");
		});

		it("POSTs the user id with the identity and returns the Store's user on 2xx", async () => {
			let seen: unknown;
			server.use(
				http.post(LINK_URL, async ({ request }) => {
					seen = await request.json();
					return HttpResponse.json(mockUser);
				}),
			);
			const out = await linking().linkFederatedIdentity?.("user-1", identity);
			expect(out).toEqual({ ok: true, user: mockUser });
			expect(seen).toEqual({ userId: "user-1", ...identity });
		});

		it("maps 403 and 401 to refused, 409 to conflict, and throws on anything else", async () => {
			answer(403);
			expect(await linking().linkFederatedIdentity?.("user-1", identity)).toEqual({
				ok: false,
				reason: "refused",
			});
			answer(401);
			expect(await linking().linkFederatedIdentity?.("user-1", identity)).toMatchObject({
				ok: false,
				reason: "refused",
			});
			answer(409);
			expect(await linking().linkFederatedIdentity?.("user-1", identity)).toEqual({
				ok: false,
				reason: "conflict",
			});
			answer(500);
			await expect(linking().linkFederatedIdentity?.("user-1", identity)).rejects.toThrow(/500/);
		});

		it("holds the link URL to https (loopback http) like the other two", () => {
			expect(
				() =>
					new HttpUserRepository({
						authenticateUrl: "https://users.example.com/auth",
						authenticateByTokenUrl: "https://users.example.com/token",
						linkFederatedIdentityUrl: "http://10.0.0.5/link",
						timeout: 5000,
					}),
			).toThrow(/linkFederatedIdentityUrl/);
		});
	});
});

// #613: D7 check 5's identity lookup over HTTP — the client of a Store that
// resolves who holds an upstream identity, and the boot-time declaration of
// which registrations that Store covers.
describe("findSubjectByFederatedIdentity over HTTP (#613)", () => {
	const LOOKUP_URL = `${BASE_URL}/user/federated-identity`;
	const REG = {
		provider: "entra-files",
		issuer: "https://login.microsoftonline.com/T-1/v2.0",
		clientId: "grants-client",
	};
	const COVER = { ...REG, requiredClaims: ["tid", "oid"] };
	const IDENTITY = { ...REG, sub: "pairwise-B", claims: { tid: "T-1", oid: "O-B" } };
	const base = {
		authenticateUrl: `${BASE_URL}/user/authenticate`,
		authenticateByTokenUrl: `${BASE_URL}/user/authenticate/token`,
		timeout: 5000,
	};
	const looking = (coverage: unknown = [COVER], over: Record<string, unknown> = {}) =>
		new HttpUserRepository({
			...base,
			findSubjectByFederatedIdentityUrl: LOOKUP_URL,
			federatedIdentityLookupCoverage: coverage as never,
			...over,
		} as never);
	const answer = (status: number, body?: unknown) =>
		server.use(
			http.post(LOOKUP_URL, () =>
				body === undefined
					? new HttpResponse(null, { status })
					: HttpResponse.json(body as never, { status }),
			),
		);
	/** The Store answers `body`, and what it was sent is recorded. */
	const store = (body: unknown, status = 200) => {
		const seen: unknown[] = [];
		server.use(
			http.post(LOOKUP_URL, async ({ request }) => {
				seen.push(await request.json());
				return HttpResponse.json(body as never, { status });
			}),
		);
		return seen;
	};

	describe("presence and construction", () => {
		it("has neither lookup method without the URL, and both with it", () => {
			const bare = new HttpUserRepository(base);
			expect(bare.supportsFederatedIdentityLookup).toBeUndefined();
			expect(bare.findSubjectByFederatedIdentity).toBeUndefined();
			const r = looking();
			expect(typeof r.supportsFederatedIdentityLookup).toBe("function");
			expect(typeof r.findSubjectByFederatedIdentity).toBe("function");
			// A URL with no coverage yet: present, covering nothing — an endpoint
			// can be staged before a connection needs it.
			const staged = looking([]);
			expect(staged.supportsFederatedIdentityLookup?.(REG, ["tid", "oid"])).toBe(false);
			expect(typeof looking(undefined).supportsFederatedIdentityLookup).toBe("function");
		});

		it("refuses coverage declared without the endpoint it would be served by", () => {
			expect(
				() =>
					new HttpUserRepository({ ...base, federatedIdentityLookupCoverage: [COVER] } as never),
			).toThrow(/findSubjectByFederatedIdentityUrl/);
		});

		it("holds the URL to the rule the other three are held to", () => {
			for (const url of [
				"http://users.example.com/lookup",
				"http://10.0.0.5/lookup",
				"https://user:pass@users.example.com/lookup",
				"",
				42,
			]) {
				expect(
					() => looking([COVER], { findSubjectByFederatedIdentityUrl: url }),
					String(url),
				).toThrow(/findSubjectByFederatedIdentityUrl/);
			}
			expect(() =>
				looking([COVER], { findSubjectByFederatedIdentityUrl: "https://users.example.com/l" }),
			).not.toThrow();
		});

		it("refuses a malformed declaration by option, entry and field, never echoing it", () => {
			const cases: [unknown, RegExp][] = [
				["not-a-list", /federatedIdentityLookupCoverage/],
				[[null], /\[0\]/],
				[[{ ...COVER, provider: undefined }], /\[0\]\.provider/],
				[[{ ...COVER, issuer: "" }], /\[0\]\.issuer/],
				[[{ ...COVER, clientId: " grants-client" }], /\[0\]\.clientId/],
				[[{ ...COVER, requiredClaims: undefined }], /\[0\]\.requiredClaims/],
				[[{ ...COVER, requiredClaims: "tid" }], /\[0\]\.requiredClaims/],
				[[{ ...COVER, requiredClaims: ["tid", "tid"] }], /\[0\]\.requiredClaims/],
				[[{ ...COVER, requiredClaims: ["a b"] }], /\[0\]\.requiredClaims/],
				[[{ ...COVER, requiredClaims: [""] }], /\[0\]\.requiredClaims/],
				[[{ ...COVER, requiredClaims: ["__proto__"] }], /\[0\]\.requiredClaims/],
				[[{ ...COVER, extra: 1 }], /\[0\]/],
				[[COVER, { ...COVER, requiredClaims: [] }], /\[1\]/],
			];
			for (const [coverage, pattern] of cases) {
				let thrown: unknown;
				try {
					looking(coverage);
				} catch (error) {
					thrown = error;
				}
				const message = (thrown as Error | undefined)?.message ?? "";
				expect(message, JSON.stringify(coverage)).toMatch(pattern);
				expect(message).not.toContain("grants-client");
			}
		});

		it("snapshots the declaration: mutating the caller's list afterwards changes nothing", () => {
			const entries = [{ ...COVER, requiredClaims: ["tid", "oid"] }];
			const r = looking(entries);
			entries[0]?.requiredClaims.push("employee_id");
			entries.pop();
			expect(r.supportsFederatedIdentityLookup?.(REG, ["tid", "oid"])).toBe(true);
		});

		it("freezes the declaration it keeps — the list, each entry, each claim list — so nothing in-process widens the probe", () => {
			// The boot probe is the check that refuses a hijacked upstream
			// account; a repository whose coverage anything holding it could push
			// onto would let that check be widened after boot (review).
			const r = looking();
			const kept = (r as unknown as { coverage: FederatedIdentityLookupCoverage[] }).coverage;
			expect(Object.isFrozen(kept)).toBe(true);
			expect(Object.isFrozen(kept[0])).toBe(true);
			expect(Object.isFrozen(kept[0]?.requiredClaims)).toBe(true);
			expect(() =>
				kept.push({ provider: "x", issuer: "y", clientId: "z", requiredClaims: [] }),
			).toThrow();
			expect(() => kept[0]?.requiredClaims.pop()).toThrow();
			expect(
				r.supportsFederatedIdentityLookup?.({ provider: "x", issuer: "y", clientId: "z" }, []),
			).toBe(false);
			expect(r.supportsFederatedIdentityLookup?.(REG, ["tid"])).toBe(false);
			// And a bare `[]` from no declaration is frozen too.
			expect(
				Object.isFrozen((looking(undefined) as unknown as { coverage: unknown }).coverage),
			).toBe(true);
		});

		it("takes a field only from the entry itself, not from its prototype, and only a list of claim names", () => {
			const inherited = Object.assign(Object.create({ ...COVER }), { provider: COVER.provider });
			expect(() => looking([inherited])).toThrow(/\[0\]\.issuer/);
			const r = looking();
			// `includes` on a string would match a substring.
			expect(
				r.supportsFederatedIdentityLookup?.(REG, "tid,oid" as unknown as readonly string[]),
			).toBe(false);
		});
	});

	describe("the probe", () => {
		it("covers exactly the declared registration, when the connection names every claim the strategy needs", () => {
			const r = looking();
			expect(r.supportsFederatedIdentityLookup?.(REG, ["tid", "oid"])).toBe(true);
			expect(r.supportsFederatedIdentityLookup?.(REG, ["oid", "tid"])).toBe(true);
			expect(r.supportsFederatedIdentityLookup?.(REG, ["oid", "tid", "employee_id"])).toBe(true);
			expect(r.supportsFederatedIdentityLookup?.(REG, ["oid"])).toBe(false);
			expect(r.supportsFederatedIdentityLookup?.(REG, [])).toBe(false);
			for (const changed of [
				{ ...REG, provider: "entra-login" },
				{ ...REG, issuer: `${REG.issuer}/` },
				{ ...REG, issuer: REG.issuer.toUpperCase() },
				{ ...REG, clientId: "login-client" },
			]) {
				expect(
					r.supportsFederatedIdentityLookup?.(changed, ["tid", "oid"]),
					JSON.stringify(changed),
				).toBe(false);
			}
		});

		it("takes an empty requirement as a strategy on the registration and sub alone", () => {
			const r = looking([{ ...REG, requiredClaims: [] }]);
			expect(r.supportsFederatedIdentityLookup?.(REG, [])).toBe(true);
			expect(r.supportsFederatedIdentityLookup?.(REG, ["oid"])).toBe(true);
		});

		it("judges two connections on one registration separately", () => {
			// Nothing is remembered from one call to the next.
			const r = looking();
			expect(r.supportsFederatedIdentityLookup?.(REG, ["tid", "oid"])).toBe(true);
			expect(r.supportsFederatedIdentityLookup?.(REG, ["tid"])).toBe(false);
			expect(r.supportsFederatedIdentityLookup?.(REG, ["tid", "oid"])).toBe(true);
		});
	});

	describe("the wire", () => {
		it("POSTs the registration, the sub and every claim the connection supplied — not only the required ones", async () => {
			const seen = store({ kind: "unlinked" });
			const claims = { tid: "T-1", oid: "O-B", employee_id: "E-9" };
			const out = await looking().findSubjectByFederatedIdentity?.({
				...REG,
				sub: "pairwise-B",
				claims,
			});
			expect(out).toStrictEqual({ kind: "unlinked" });
			expect(seen).toEqual([{ ...REG, sub: "pairwise-B", claims }]);
		});

		it("sends an empty claims object when the connection named none", async () => {
			const seen = store({ kind: "unlinked" });
			await looking([{ ...REG, requiredClaims: [] }]).findSubjectByFederatedIdentity?.({
				...REG,
				sub: "s",
				claims: {},
			});
			expect((seen[0] as { claims: unknown }).claims).toEqual({});
		});

		it("reads each of the port's answers, as a fresh object of the contract's fields only", async () => {
			const answers: [unknown, unknown][] = [
				[
					{ kind: "linked", subject: "u-bob" },
					{ kind: "linked", subject: "u-bob" },
				],
				[{ kind: "unlinked" }, { kind: "unlinked" }],
				[
					{ kind: "indeterminate", reason: "registration_not_covered" },
					{ kind: "indeterminate", reason: "registration_not_covered" },
				],
				[
					{ kind: "indeterminate", reason: "identity_not_resolvable" },
					{ kind: "indeterminate", reason: "identity_not_resolvable" },
				],
				// A Store may say more; the client carries none of it on.
				[{ kind: "unlinked", checkedAt: "2026-09-22", tid: "T-1" }, { kind: "unlinked" }],
				[
					{ kind: "linked", subject: " u-bob ", extra: true },
					{ kind: "linked", subject: " u-bob " },
				],
			];
			for (const [body, expected] of answers) {
				answer(200, body);
				expect(
					await looking().findSubjectByFederatedIdentity?.(IDENTITY),
					JSON.stringify(body),
				).toStrictEqual(expected);
			}
		});

		it("throws on any status but a 2xx, whatever the body says — a 404 is not nobody", async () => {
			for (const status of [401, 403, 404, 409, 429, 500, 503]) {
				answer(status, { kind: "unlinked" });
				await expect(
					looking().findSubjectByFederatedIdentity?.(IDENTITY),
					String(status),
				).rejects.toThrow(new RegExp(`HTTP ${status}`));
			}
		});

		it("throws on a 2xx whose body is not one of the three answers", async () => {
			const bodies: [number, unknown][] = [
				[200, undefined],
				[204, undefined],
				[200, null],
				[200, "unlinked"],
				[200, ["unlinked"]],
				[200, {}],
				[200, { kind: "nobody" }],
				[200, { kind: "linked" }],
				[200, { kind: "linked", subject: "" }],
				[200, { kind: "linked", subject: 7 }],
				[200, { kind: "linked", subject: ["u1", "u2"] }],
				[200, { kind: "indeterminate" }],
				[200, { kind: "indeterminate", reason: "shrug" }],
			];
			for (const [status, body] of bodies) {
				answer(status, body);
				await expect(
					looking().findSubjectByFederatedIdentity?.(IDENTITY),
					`${status} ${JSON.stringify(body)}`,
				).rejects.toThrow(/HttpUserRepository/);
			}
			server.use(http.post(LOOKUP_URL, () => new HttpResponse("not json", { status: 200 })));
			await expect(looking().findSubjectByFederatedIdentity?.(IDENTITY)).rejects.toThrow(
				/non-JSON/,
			);
		});

		it("answers without asking when the registration is not declared, or a required claim is not there", async () => {
			const seen = store({ kind: "unlinked" });
			const r = looking();
			expect(
				await r.findSubjectByFederatedIdentity?.({ ...IDENTITY, clientId: "login-client" }),
			).toStrictEqual({ kind: "indeterminate", reason: "registration_not_covered" });
			expect(
				await r.findSubjectByFederatedIdentity?.({ ...IDENTITY, claims: { tid: "T-1" } }),
			).toStrictEqual({ kind: "indeterminate", reason: "identity_not_resolvable" });
			expect(
				await r.findSubjectByFederatedIdentity?.({ ...IDENTITY, claims: { tid: "T-1", oid: "" } }),
			).toStrictEqual({ kind: "indeterminate", reason: "identity_not_resolvable" });
			expect(seen).toEqual([]);
		});

		it("never follows a redirect: the body carries identity, and the other endpoint hears nothing", async () => {
			const elsewhere = `${BASE_URL}/elsewhere`;
			let heard = 0;
			server.use(
				http.post(
					LOOKUP_URL,
					() => new HttpResponse(null, { status: 307, headers: { Location: elsewhere } }),
				),
				http.post(elsewhere, () => {
					heard += 1;
					return HttpResponse.json({ kind: "unlinked" });
				}),
			);
			await expect(looking().findSubjectByFederatedIdentity?.(IDENTITY)).rejects.toThrow(
				/HTTP 307/,
			);
			expect(heard).toBe(0);
		});

		it("carries nothing of the identity or the body in what it throws", async () => {
			const cases: (() => Response)[] = [
				() => HttpResponse.json({ kind: "nobody", echo: "pairwise-B O-B" }),
				() => new HttpResponse("pairwise-B O-B", { status: 500, statusText: "O-B pairwise-B" }),
				() => new HttpResponse("pairwise-B", { status: 200 }),
			];
			for (const respond of cases) {
				server.use(http.post(LOOKUP_URL, respond));
				let thrown: unknown;
				try {
					await looking().findSubjectByFederatedIdentity?.(IDENTITY);
				} catch (error) {
					thrown = error;
				}
				const text = `${(thrown as Error).message} ${String((thrown as Error).cause ?? "")}`;
				expect(text).not.toContain("pairwise-B");
				expect(text).not.toContain("O-B");
			}
		});

		it("aborts the request at the deadline rather than waiting for headers that never come", async () => {
			// The deadline race in the body read covers a stalled body; headers
			// that never arrive are the abort signal's to cut, and without it the
			// caller would still be told "timed out" — after the upstream finally
			// answered. So the failure must land before the upstream does.
			server.use(
				http.post(LOOKUP_URL, async () => {
					await delay(400);
					return HttpResponse.json({ kind: "unlinked" });
				}),
			);
			const started = Date.now();
			await expect(
				looking([COVER], { timeout: 20 }).findSubjectByFederatedIdentity?.(IDENTITY),
			).rejects.toThrow(/timed out after 20ms/);
			expect(Date.now() - started).toBeLessThan(250);
		});

		it("reports a transport that failed before any response with a fixed message, and no cause", async () => {
			// What a transport reports may quote what it was sending; the client
			// says only that the endpoint could not be reached.
			server.use(http.post(LOOKUP_URL, () => HttpResponse.error()));
			let thrown: unknown;
			try {
				await looking().findSubjectByFederatedIdentity?.(IDENTITY);
			} catch (error) {
				thrown = error;
			}
			expect((thrown as Error).message).toMatch(/identity lookup at .* could not be reached/);
			expect((thrown as Error).cause).toBeUndefined();
		});

		it("holds the exchange to the timeout and the body cap, as the other endpoints are", async () => {
			server.use(
				http.post(LOOKUP_URL, async () => {
					await delay(300);
					return HttpResponse.json({ kind: "unlinked" });
				}),
			);
			await expect(
				looking([COVER], { timeout: 20 }).findSubjectByFederatedIdentity?.(IDENTITY),
			).rejects.toThrow(/timed out after 20ms/);

			server.use(
				http.post(LOOKUP_URL, () => {
					const stream = new ReadableStream<Uint8Array>({
						start(ctrl) {
							ctrl.enqueue(new TextEncoder().encode('{"kind":'));
						},
					});
					return new HttpResponse(stream, { status: 200 });
				}),
			);
			await expect(
				looking([COVER], { timeout: 30 }).findSubjectByFederatedIdentity?.(IDENTITY),
			).rejects.toThrow(/timed out after 30ms/);

			answer(200, { kind: "unlinked", padding: "x".repeat(600) });
			await expect(
				looking([COVER], { maxResponseBytes: 256 }).findSubjectByFederatedIdentity?.(IDENTITY),
			).rejects.toThrow(/exceeds the 256-byte cap/);
		});

		it("asks every time: nothing is cached and nothing is retried", async () => {
			let calls = 0;
			server.use(
				http.post(LOOKUP_URL, () => {
					calls += 1;
					return HttpResponse.json(
						calls === 1 ? { kind: "unlinked" } : { kind: "linked", subject: "u-bob" },
					);
				}),
			);
			const r = looking();
			expect(await r.findSubjectByFederatedIdentity?.(IDENTITY)).toStrictEqual({
				kind: "unlinked",
			});
			expect(await r.findSubjectByFederatedIdentity?.(IDENTITY)).toStrictEqual({
				kind: "linked",
				subject: "u-bob",
			});
			expect(calls).toBe(2);
		});
	});
});
