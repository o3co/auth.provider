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

/**
 * The guards on revocation fetching. Every case here is a request this
 * process must not make, or a response it must not read to the end — the
 * limits that make "retrieve a URL out of a certificate" a safe operation
 * rather than an SSRF primitive.
 */

import { describe, expect, it, vi } from "vitest";
import { createGuardedFetch } from "#/fullPki/fetchGuard.mjs";

const options = {
	allowedHosts: ["crl.example.test", "other.test:8443"],
	timeoutMs: 50,
	maxBytes: 1024,
};

const okResponse = (bytes: Uint8Array) =>
	new Response(bytes as unknown as BodyInit, { status: 200 });

describe("guarded fetch — destination", () => {
	it("fetches an allowlisted host", async () => {
		const fetchImpl = vi.fn(async () => okResponse(new Uint8Array([1, 2, 3])));
		const get = createGuardedFetch({
			...options,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		const result = await get("http://crl.example.test/a.crl");
		expect(result.ok).toBe(true);
		if (result.ok) expect(Array.from(result.bytes)).toEqual([1, 2, 3]);
	});

	it("refuses a host that is not allowlisted, without issuing the request", async () => {
		// The cloud metadata service is the canonical target: it answers on a
		// plain HTTP GET from inside the network and nowhere else.
		const fetchImpl = vi.fn();
		const get = createGuardedFetch({
			...options,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		const result = await get("http://169.254.169.254/latest/meta-data/");
		expect(result).toMatchObject({ ok: false, reason: "host_not_allowed" });
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("fetches from a private address the operator allowlisted — the allowlist, not RFC 6890, is this guard's control", async () => {
		// A deliberate divergence from core's `isSpecialUseAddress` (v0.13.0
		// audit): an internal CA publishes its CRLs and runs its OCSP responder
		// inside the network, so refusing special-use addresses here would refuse
		// the deployments mTLS is for. The destination is one the operator named,
		// not one a stranger chose, which is the case the special-use list is for.
		const fetchImpl = vi.fn(async () => okResponse(new Uint8Array([9])));
		const get = createGuardedFetch({
			...options,
			allowedHosts: ["10.20.30.40", "pki.corp.internal"],
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect((await get("http://10.20.30.40/ca.crl")).ok).toBe(true);
		expect((await get("http://pki.corp.internal/ca.crl")).ok).toBe(true);
		expect(fetchImpl).toHaveBeenCalledTimes(2);
	});

	it("matches an allowlist entry's port when it names one", async () => {
		const fetchImpl = vi.fn(async () => okResponse(new Uint8Array([1])));
		const get = createGuardedFetch({
			...options,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect((await get("https://other.test:8443/a.crl")).ok).toBe(true);
		expect(await get("https://other.test/a.crl")).toMatchObject({
			ok: false,
			reason: "host_not_allowed",
		});
	});

	it("refuses a non-HTTP scheme", async () => {
		const fetchImpl = vi.fn();
		const get = createGuardedFetch({
			...options,
			allowedHosts: ["crl.example.test"],
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		// `file:` would read the local filesystem; `ldap:` is a legal CRL
		// distribution scheme this module does not speak.
		expect(await get("file:///etc/passwd")).toMatchObject({
			ok: false,
			reason: "scheme_not_allowed",
		});
		expect(await get("ldap://crl.example.test/cn=CRL")).toMatchObject({
			ok: false,
			reason: "scheme_not_allowed",
		});
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("refuses a URL carrying credentials", async () => {
		const fetchImpl = vi.fn();
		const get = createGuardedFetch({
			...options,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		const result = await get("http://user:pass@crl.example.test/a.crl");
		expect(result).toMatchObject({ ok: false, reason: "url_has_credentials" });
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("does not follow redirects", async () => {
		// A redirect names a second destination the allowlist never saw. Asking
		// for `redirect: "manual"` and refusing the 3xx it hands back is what
		// makes an allowlisted host unable to act as an open proxy to
		// everything it can reach — and names the refusal by its status.
		const fetchImpl = vi.fn(async (_url: unknown, init: RequestInit) => {
			expect(init.redirect).toBe("manual");
			return new Response(null, {
				status: 307,
				headers: { location: "http://169.254.169.254/latest/meta-data/" },
			});
		});
		const get = createGuardedFetch({
			...options,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect(await get("http://crl.example.test/a.crl")).toEqual({
			ok: false,
			reason: "redirect_refused",
			detail: "HTTP 307",
		});
		expect(fetchImpl).toHaveBeenCalledTimes(1);
	});

	it("reads no error's text: a fetch error that mentions a redirect is a network error", async () => {
		// undici used to be asked for `redirect: "error"`, which it reports as
		// TypeError("fetch failed") with "unexpected redirect" on the cause and
		// no code — so the text was all there was to classify by. A redirect is
		// now a status; an error's message is the library's, and is never read.
		const fetchImpl = vi.fn(async () => {
			throw new TypeError("fetch failed", { cause: new Error("unexpected redirect") });
		});
		const get = createGuardedFetch({
			...options,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect(await get("http://crl.example.test/a.crl")).toMatchObject({
			ok: false,
			reason: "network_error",
			detail: "fetch failed",
			cause: expect.any(TypeError),
		});
	});

	it("matches an IPv6 literal in the allowlist against the URL's bracketed hostname", async () => {
		// WHATWG `URL.hostname` keeps the brackets on an IPv6 literal (`[::1]`)
		// while the allowlist parser stripped them, so an IPv6 entry could never
		// match. Both sides are normalised to the canonical bracket-less form.
		const fetchImpl = vi.fn(async () => okResponse(new Uint8Array([1])));
		const get = createGuardedFetch({
			...options,
			allowedHosts: ["[::1]:8080", "[fd00:0:0:0:0:0:0:7]", "2001:db8::1"],
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect((await get("http://[::1]:8080/a.crl")).ok).toBe(true);
		// A port-qualified entry still refuses another port.
		expect(await get("http://[::1]:9090/a.crl")).toMatchObject({
			ok: false,
			reason: "host_not_allowed",
		});
		// An entry in expanded form matches the URL's compressed serialisation.
		expect((await get("http://[fd00::7]/a.crl")).ok).toBe(true);
		// A bare literal without brackets is a host, not `host:port`.
		expect((await get("http://[2001:db8::1]/a.crl")).ok).toBe(true);
	});
});

describe("guarded fetch — response limits", () => {
	it("refuses a response larger than the cap even when Content-Length lies", async () => {
		// The declared length is a claim by the responder. The running total is
		// what actually stops the read.
		const oversized = new Uint8Array(4096);
		const fetchImpl = vi.fn(
			async () =>
				new Response(oversized as unknown as BodyInit, {
					status: 200,
					headers: { "content-length": "10" },
				}),
		);
		const get = createGuardedFetch({
			...options,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect(await get("http://crl.example.test/a.crl")).toMatchObject({
			ok: false,
			reason: "response_too_large",
		});
	});

	it("refuses on a declared Content-Length over the cap", async () => {
		const fetchImpl = vi.fn(
			async () =>
				new Response(new Uint8Array([1]) as unknown as BodyInit, {
					status: 200,
					headers: { "content-length": "999999" },
				}),
		);
		const get = createGuardedFetch({
			...options,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect(await get("http://crl.example.test/a.crl")).toMatchObject({
			ok: false,
			reason: "response_too_large",
		});
	});

	it("reports a non-2xx status as an http error rather than empty bytes", async () => {
		const fetchImpl = vi.fn(async () => new Response(null, { status: 503 }));
		const get = createGuardedFetch({
			...options,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect(await get("http://crl.example.test/a.crl")).toMatchObject({
			ok: false,
			reason: "http_error",
		});
	});

	it.each([
		["an HTTP error", { status: 503 }, {}, "http_error"],
		[
			"an unexpected Content-Type",
			{ status: 200, headers: { "content-type": "text/html" } },
			{ expectContentType: "application/ocsp-response" },
			"unexpected_content_type",
		],
		[
			"a Content-Length above the cap",
			{ status: 200, headers: { "content-length": "999999" } },
			{},
			"response_too_large",
		],
	] as const)("releases the body it will not read: %s", async (_label, init, request, reason) => {
		// A refusal made before the body is read must cancel it, or the
		// connection stays held until the peer gives up.
		let cancelled = false;
		const body = new ReadableStream<Uint8Array>({
			pull(controller) {
				controller.enqueue(new Uint8Array(16));
			},
			cancel() {
				cancelled = true;
			},
		});
		const fetchImpl = vi.fn(async () => new Response(body, init));
		const get = createGuardedFetch({
			...options,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect(await get("http://crl.example.test/a.crl", request)).toMatchObject({
			ok: false,
			reason,
		});
		expect(cancelled).toBe(true);
	});

	it("times out a responder that never answers", async () => {
		const fetchImpl = vi.fn(
			(_url: unknown, init: RequestInit) =>
				new Promise<Response>((_resolve, reject) => {
					init.signal?.addEventListener("abort", () =>
						reject(new DOMException("aborted", "AbortError")),
					);
				}),
		);
		const get = createGuardedFetch({
			...options,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect(await get("http://crl.example.test/a.crl")).toMatchObject({
			ok: false,
			reason: "timeout",
		});
	});

	it("reports an unparseable URL rather than throwing", async () => {
		const get = createGuardedFetch({
			...options,
			fetchImpl: vi.fn() as unknown as typeof fetch,
		});
		expect(await get("not a url")).toMatchObject({ ok: false, reason: "url_unparseable" });
	});
});

describe("guarded fetch — POST, for OCSP (#431)", () => {
	const body = new Uint8Array([0x30, 0x00]);
	const ocspRequest = {
		method: "POST" as const,
		body,
		contentType: "application/ocsp-request",
		accept: "application/ocsp-response",
		expectContentType: "application/ocsp-response",
	};
	const typed = (bytes: Uint8Array, contentType: string) =>
		new Response(bytes as unknown as BodyInit, {
			status: 200,
			headers: { "content-type": contentType },
		});

	it("sends the body with its content type and accept header, and still refuses redirects", async () => {
		const fetchImpl = vi.fn(async (_url: unknown, init: RequestInit) => {
			expect(init.method).toBe("POST");
			expect(init.body).toBe(body);
			expect(init.redirect).toBe("manual");
			expect(init.credentials).toBe("omit");
			const headers = init.headers as Record<string, string>;
			expect(headers["content-type"]).toBe("application/ocsp-request");
			expect(headers.accept).toBe("application/ocsp-response");
			return typed(new Uint8Array([1, 2]), "application/ocsp-response");
		});
		const post = createGuardedFetch({
			...options,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		const result = await post("http://crl.example.test/ocsp", ocspRequest);
		expect(result.ok).toBe(true);
		if (result.ok) expect(Array.from(result.bytes)).toEqual([1, 2]);
		expect(fetchImpl).toHaveBeenCalledTimes(1);
	});

	it("refuses a response whose Content-Type is not the one expected", async () => {
		// A captive portal or an error page answers 200 with HTML. Reading that
		// as an OCSP response only costs a parse failure, but the guard is
		// where "the responder did not answer as a responder" is named.
		const fetchImpl = vi.fn(async () => typed(new Uint8Array([1]), "text/html; charset=utf-8"));
		const post = createGuardedFetch({
			...options,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect(await post("http://crl.example.test/ocsp", ocspRequest)).toMatchObject({
			ok: false,
			reason: "unexpected_content_type",
		});
	});

	it("matches the expected media type ignoring parameters and case", async () => {
		const fetchImpl = vi.fn(async () =>
			typed(new Uint8Array([1]), "Application/OCSP-Response; charset=binary"),
		);
		const post = createGuardedFetch({
			...options,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect((await post("http://crl.example.test/ocsp", ocspRequest)).ok).toBe(true);
	});

	it("applies the host allowlist to a POST exactly as to a GET", async () => {
		const fetchImpl = vi.fn();
		const post = createGuardedFetch({
			...options,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect(await post("http://169.254.169.254/latest/meta-data/", ocspRequest)).toMatchObject({
			ok: false,
			reason: "host_not_allowed",
		});
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("does not check the content type when the caller expects none", async () => {
		// The CRL path: distribution points answer with application/pkix-crl,
		// application/octet-stream, or nothing useful, and the bytes are what
		// count.
		const fetchImpl = vi.fn(async () => typed(new Uint8Array([1]), "text/plain"));
		const get = createGuardedFetch({
			...options,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});

		expect((await get("http://crl.example.test/a.crl")).ok).toBe(true);
	});
});
