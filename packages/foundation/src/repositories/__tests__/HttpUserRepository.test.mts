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
import { DEFAULT_MAX_RESPONSE_BYTES, HttpUserRepository } from "../HttpUserRepository.mjs";

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
});
