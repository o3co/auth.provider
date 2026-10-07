import { assert, describe, expect, it } from "vitest";
import {
	effectiveSources,
	hashSourceOf,
	iframeSrcsOf,
	parsePolicy,
	scriptsOf,
} from "../../__tests__/_helpers/frontchannelPage.mjs";
import { createMockLogger, type MockLogger } from "../../__tests__/_helpers/mockLogger.mjs";
import {
	expectBestEffortWarn,
	expectUriNotLogged,
} from "../../__tests__/_helpers/projectedLog.mjs";
import {
	type FrontchannelRP,
	renderFrontchannelLogoutHtml,
	renderFrontchannelLogoutPage,
} from "../renderFrontchannel.mjs";

describe("renderFrontchannelLogoutHtml", () => {
	it("emits one iframe per RP with frontchannelLogoutUri", () => {
		const html = renderFrontchannelLogoutHtml({
			rps: [
				{
					clientId: "rp1",
					frontchannelLogoutUri: "https://rp1.example/fc",
					frontchannelLogoutSessionRequired: true,
				},
				{
					clientId: "rp2",
					frontchannelLogoutUri: "https://rp2.example/fc",
					frontchannelLogoutSessionRequired: true,
				},
				{ clientId: "rp3" }, // no frontchannelLogoutUri — skipped
			],
			issuer: "https://auth.example",
			sid: "sid-1",
		});
		expect(html).toContain("https://rp1.example/fc");
		expect(html).toContain("https://rp2.example/fc");
		expect(html).not.toContain("rp3");
		expect([...html.matchAll(/<iframe/g)].length).toBe(2);
	});

	it("appends iss + sid query params to iframe URLs when frontchannelLogoutSessionRequired: true", () => {
		const html = renderFrontchannelLogoutHtml({
			rps: [
				{
					clientId: "rp",
					frontchannelLogoutUri: "https://rp.example/fc",
					frontchannelLogoutSessionRequired: true,
				},
			],
			issuer: "https://auth.example",
			sid: "sid-1",
		});
		// Because HTML-escaping converts & → &amp;, check either form defensively.
		expect(html).toMatch(
			/https:\/\/rp\.example\/fc\?iss=https%3A%2F%2Fauth\.example(?:&|&amp;)sid=sid-1/,
		);
	});

	it("omits sid when frontchannelLogoutSessionRequired: false", () => {
		const html = renderFrontchannelLogoutHtml({
			rps: [
				{
					clientId: "rp",
					frontchannelLogoutUri: "https://rp.example/fc",
					frontchannelLogoutSessionRequired: false,
				},
			],
			issuer: "iss",
			sid: "sid-1",
		});
		expect(html).toMatch(/https:\/\/rp\.example\/fc\?iss=/);
		expect(html).not.toContain("sid=sid-1");
	});

	it("includes sid by default when frontchannelLogoutSessionRequired is undefined", () => {
		const html = renderFrontchannelLogoutHtml({
			rps: [{ clientId: "rp", frontchannelLogoutUri: "https://rp.example/fc" }],
			issuer: "iss",
			sid: "sid-1",
		});
		expect(html).toContain("sid=sid-1");
	});

	it("iframe URL with untrusted chars is neutralized (percent-encoded by URL normalization)", () => {
		const html = renderFrontchannelLogoutHtml({
			rps: [
				{
					clientId: "evil",
					frontchannelLogoutUri: 'https://evil.example/fc?x="><script>alert(1)</script>',
					frontchannelLogoutSessionRequired: false,
				},
			],
			issuer: "iss",
			sid: "sid",
		});
		// Whatever encoding form, the raw injection must not appear:
		expect(html).not.toContain('"><script>alert(1)</script>');
		// new URL() percent-encodes `<`, `>`, `"`, `(`, `)`, `/` during normalization.
		// The closing tag encodes as %3C%2Fscript%3E (%2F = '/'):
		expect(html).toMatch(/%3Cscript%3Ealert%281%29%3C%2Fscript%3E/);
	});

	it("preserves fragment in frontchannelLogoutUri (fragment must come after query)", () => {
		const html = renderFrontchannelLogoutHtml({
			rps: [{ clientId: "rp", frontchannelLogoutUri: "https://rp.example/fc#app-route" }],
			issuer: "https://auth.example",
			sid: "sid-1",
		});
		// Expected: ...fc?iss=...&sid=...#app-route
		// Find the iframe src attribute content (HTML-escaped form in output)
		const match = html.match(/<iframe src="([^"]+)"/);
		assert(match !== null, "expected an iframe src in the rendered HTML");
		const src = (match[1] ?? "").replace(/&amp;/g, "&"); // undo HTML escape
		// Query params come before fragment:
		const queryIdx = src.indexOf("?");
		const fragIdx = src.indexOf("#");
		expect(queryIdx).toBeGreaterThan(-1);
		expect(fragIdx).toBeGreaterThan(queryIdx);
		// Fragment is preserved:
		expect(src).toContain("#app-route");
		// Both params are in the query portion:
		expect(src.substring(queryIdx, fragIdx)).toContain("iss=");
		expect(src.substring(queryIdx, fragIdx)).toContain("sid=sid-1");
	});

	it("appends to existing query string with `&` separator", () => {
		const html = renderFrontchannelLogoutHtml({
			rps: [{ clientId: "rp", frontchannelLogoutUri: "https://rp.example/fc?tenant=foo" }],
			issuer: "iss",
			sid: "sid-1",
		});
		const match = html.match(/<iframe src="([^"]+)"/);
		assert(match !== null, "expected an iframe src in the rendered HTML");
		const src = (match[1] ?? "").replace(/&amp;/g, "&");
		expect(src).toMatch(/^https:\/\/rp\.example\/fc\?tenant=foo&iss=iss&sid=sid-1$/);
	});

	it("includes referrerpolicy=no-referrer on each iframe (Front-Channel Logout §2 hardening)", () => {
		const html = renderFrontchannelLogoutHtml({
			rps: [
				{ clientId: "rp1", frontchannelLogoutUri: "https://rp1.example/fc" },
				{ clientId: "rp2", frontchannelLogoutUri: "https://rp2.example/fc" },
			],
			issuer: "iss",
			sid: "sid",
		});
		const iframeCount = (html.match(/<iframe[^>]*referrerpolicy="no-referrer"/g) ?? []).length;
		expect(iframeCount).toBe(2);
	});

	it("redirects to postLogoutRedirect via setTimeout when provided", () => {
		const html = renderFrontchannelLogoutHtml({
			rps: [],
			issuer: "iss",
			sid: "sid",
			postLogoutRedirect: { uri: "https://rp.example/logged-out" },
		});
		expect(html).toContain("https://rp.example/logged-out");
		expect(html).toMatch(/window\.location\.href/);
		expect(html).toMatch(/setTimeout/);
	});

	it("uses custom redirectDelayMs when provided", () => {
		const html = renderFrontchannelLogoutHtml({
			rps: [],
			issuer: "iss",
			sid: "sid",
			postLogoutRedirect: { uri: "https://rp.example/logged-out" },
			redirectDelayMs: 500,
		});
		expect(scriptsOf(html)[0]?.attributes["data-delay"]).toBe("500");
	});

	it("no redirect script when postLogoutRedirect is absent", () => {
		const html = renderFrontchannelLogoutHtml({
			rps: [{ clientId: "rp", frontchannelLogoutUri: "https://rp.example/fc" }],
			issuer: "iss",
			sid: "sid",
		});
		expect(html).not.toContain("setTimeout");
		expect(html).not.toContain("window.location.href");
	});

	it("skips RPs with invalid frontchannelLogoutUri instead of throwing", () => {
		const logger = createMockLogger();
		const html = renderFrontchannelLogoutHtml({
			rps: [
				{ clientId: "good", frontchannelLogoutUri: "https://good.example/fc" },
				{ clientId: "bad", frontchannelLogoutUri: "not-a-url" },
			],
			issuer: "https://auth.example",
			sid: "sid-1",
			logger,
		});
		// good RP still produces an iframe
		expect(html).toContain("good.example");
		// bad RP is skipped
		expect(html).not.toContain("not-a-url");
		// exactly one iframe in the output
		expect([...html.matchAll(/<iframe/g)].length).toBe(1);
		// one structured warning for the bad RP, refused before an iframe URL is built
		expectBestEffortWarn(
			logger,
			"logout_frontchannel_uri_refused",
			{ site: "logout", clientId: "bad", reason: "unparsable" },
			null,
		);
	});

	it("skips an RP whose iframe URL cannot be built instead of throwing", () => {
		const logger = createMockLogger();
		const html = renderFrontchannelLogoutHtml({
			rps: [
				{ clientId: "good", frontchannelLogoutUri: "https://good.example/fc" },
				{
					clientId: "bad",
					frontchannelLogoutUri: "https://bad.example/fc",
					get frontchannelLogoutSessionRequired(): boolean {
						throw new TypeError("field unavailable");
					},
				},
			],
			issuer: "https://auth.example",
			sid: "sid-1",
			logger,
		});
		expect(html).toContain("good.example");
		expect(html).not.toContain("bad.example");
		expect([...html.matchAll(/<iframe/g)].length).toBe(1);
		expectBestEffortWarn(
			logger,
			"logout_frontchannel_iframe_skipped",
			{ clientId: "bad" },
			"TypeError",
		);
	});

	describe("a frontchannelLogoutUri must be http(s)", () => {
		const render = (rps: ReadonlyArray<FrontchannelRP>, logger: MockLogger): string =>
			renderFrontchannelLogoutHtml({
				rps: [{ clientId: "good", frontchannelLogoutUri: "https://good.example/fc" }, ...rps],
				issuer: "https://auth.example",
				sid: "sid-1",
				logger,
			});
		const iframeSrcs = (html: string): string[] =>
			[...html.matchAll(/<iframe src="([^"]*)"/g)].map((m) => m[1] ?? "");

		it.each([
			["lower case", "javascript:void(0)"],
			["upper case", "JAVASCRIPT:void(0)"],
			// The URL parser strips the tab, so this parses as the lower-case value.
			["a tab inside the scheme", "java\tscript:void(0)"],
			["a data URL", "data:text/plain,signed-out"],
			["a blob URL", "blob:https://rp.example/x"],
			["a custom scheme", "com.example.app:/x"],
			["an ftp URL", "ftp://rp.example/fc"],
		])(
			"refuses a non-http(s) scheme (%s) stored for an RP: never rendered, the other RPs are, one warn names the reason, never the URI",
			(_label, uri) => {
				const logger = createMockLogger();
				const html = render([{ clientId: "rp", frontchannelLogoutUri: uri }], logger);

				expect(iframeSrcs(html)).toEqual([
					"https://good.example/fc?iss=https%3A%2F%2Fauth.example&amp;sid=sid-1",
				]);
				expect(logger.warn).toHaveBeenCalledTimes(1);
				expectBestEffortWarn(
					logger,
					"logout_frontchannel_uri_refused",
					{ site: "logout", clientId: "rp", reason: "not-http" },
					null,
				);
				expectUriNotLogged(logger, uri);
			},
		);

		it("reads a refused RP's clientId once", () => {
			const logger = createMockLogger();
			let reads = 0;
			render(
				[
					{
						get clientId(): string {
							reads += 1;
							return "rp";
						},
						frontchannelLogoutUri: "ftp://rp.example/fc",
					},
				],
				logger,
			);
			expect(reads).toBe(1);
		});

		it("refuses a non-http(s) scheme without throwing when the logger throws", () => {
			const logger = createMockLogger();
			logger.warn.mockImplementation(() => {
				throw new Error("logger unavailable");
			});
			const html = render(
				[{ clientId: "rp", frontchannelLogoutUri: "ftp://rp.example/fc" }],
				logger,
			);
			expect(iframeSrcs(html)).toHaveLength(1);
		});

		it("refuses a value that is not a string, and one whose read throws", () => {
			const logger = createMockLogger();
			const html = render(
				[
					{ clientId: "number", frontchannelLogoutUri: 42 as unknown as string },
					{
						clientId: "throws",
						get frontchannelLogoutUri(): string {
							throw new Error("field unavailable");
						},
					},
				],
				logger,
			);

			expect(iframeSrcs(html)).toHaveLength(1);
			expect(logger.warn).toHaveBeenCalledTimes(2);
			expectBestEffortWarn(
				logger,
				"logout_frontchannel_uri_refused",
				{ site: "logout", clientId: "number", reason: "not-a-string" },
				null,
			);
			expectBestEffortWarn(
				logger,
				"logout_frontchannel_uri_refused",
				{ site: "logout", clientId: "throws", reason: "unreadable" },
				null,
			);
		});

		it("refuses a non-http(s) scheme for an RP whose clientId read throws, logging it without one", () => {
			const logger = createMockLogger();
			const html = render(
				[
					{
						get clientId(): string {
							throw new Error("field unavailable");
						},
						frontchannelLogoutUri: "ftp://rp.example/fc",
					},
				],
				logger,
			);

			expect(iframeSrcs(html)).toHaveLength(1);
			expectBestEffortWarn(
				logger,
				"logout_frontchannel_uri_refused",
				{ site: "logout", clientId: undefined, reason: "not-http" },
				null,
			);
		});

		it("renders an http(s) URI on any host, with a fragment or a query, and skips an absent one, without a warn", () => {
			const logger = createMockLogger();
			const html = render(
				[
					{ clientId: "http", frontchannelLogoutUri: "http://rp.example/fc" },
					{ clientId: "fragment", frontchannelLogoutUri: "https://rp.example/fc#app-route" },
					{ clientId: "query", frontchannelLogoutUri: "https://rp.example/fc?state=a" },
					{ clientId: "null", frontchannelLogoutUri: null as unknown as string },
					{ clientId: "empty", frontchannelLogoutUri: "" },
					{ clientId: "none" },
				],
				logger,
			);

			expect(iframeSrcs(html)).toHaveLength(4);
			expect(logger.warn).not.toHaveBeenCalled();
		});
	});

	describe("the iframe src attribute is escaped", () => {
		const srcOf = (uri: string): string => {
			const html = renderFrontchannelLogoutHtml({
				rps: [{ clientId: "rp", frontchannelLogoutUri: uri }],
				issuer: "https://auth.example",
				sid: "sid-1",
			});
			// The whole tag: a src that ended early would not be followed by ` hidden`.
			const match = html.match(
				/<iframe src="([^"]*)" hidden aria-hidden="true" referrerpolicy="no-referrer"><\/iframe>/,
			);
			assert(match !== null, "expected one well-formed iframe");
			return match[1] ?? "";
		};

		const ISS_SID = "iss=https%3A%2F%2Fauth.example&amp;sid=sid-1";
		it.each([
			["a double quote", 'https://rp.example/a"b', `https://rp.example/a%22b?${ISS_SID}`],
			["a single quote", "https://rp.example/a'b", `https://rp.example/a&#39;b?${ISS_SID}`],
			["a less-than sign", "https://rp.example/a<b", `https://rp.example/a%3Cb?${ISS_SID}`],
			[
				"an ampersand",
				"https://rp.example/fc?a=1&b=2",
				`https://rp.example/fc?a=1&amp;b=2&amp;${ISS_SID}`,
			],
		])("renders an https URI carrying %s escaped in the src", (_label, uri, expected) => {
			expect(srcOf(uri)).toBe(expected);
		});
	});

	describe("redirectDelayMs is a non-negative whole number of milliseconds", () => {
		const delayIn = (redirectDelayMs: number): string => {
			const html = renderFrontchannelLogoutHtml({
				rps: [],
				issuer: "iss",
				sid: "sid",
				postLogoutRedirect: { uri: "https://rp.example/logged-out" },
				redirectDelayMs,
			});
			const delay = scriptsOf(html)[0]?.attributes["data-delay"];
			assert(delay !== undefined, "expected the redirect script");
			return delay;
		};

		it.each([
			["NaN", Number.NaN, "2000"],
			["Infinity", Number.POSITIVE_INFINITY, "2000"],
			["a negative number", -5, "2000"],
			["a fraction", 1500.7, "1500"],
			["a value that is not a number", "soon" as unknown as number, "2000"],
			["zero", 0, "0"],
		])("writes %s onto the script as a whole number", (_label, value, expected) => {
			expect(delayIn(value)).toBe(expected);
		});
	});

	describe("the post-logout redirect is a checked base plus the RP's state", () => {
		const render = (postLogoutRedirect: unknown, logger: MockLogger): string =>
			renderFrontchannelLogoutHtml({
				rps: [{ clientId: "rp", frontchannelLogoutUri: "https://rp.example/fc" }],
				issuer: "https://auth.example",
				sid: "sid-1",
				postLogoutRedirect: postLogoutRedirect as { uri: string; state?: string },
				logger,
			});
		/** The URL the page's script sends the browser to, or `undefined` for no script. */
		const targetOf = (html: string): string | undefined =>
			scriptsOf(html)[0]?.attributes["data-target"];

		it.each([
			["a non-http(s) scheme", "data:text/plain,signed-out", "executable-scheme"],
			["a scheme that is not reverse-domain", "ftp://rp.example/out", "scheme-not-reverse-domain"],
			["plain http off a loopback host", "http://rp.example/out", "http-non-loopback"],
			["a base that already carries state", "https://rp.example/out?state=x", "reserved-parameter"],
			["a base with a fragment", "https://rp.example/out#done", "fragment"],
			["a value that is not a URL", "not-a-url", "unparsable"],
		])(
			"refuses %s: the page keeps its iframes, has no redirect script, and one warn names the reason, never the URI",
			(_label, uri, reason) => {
				const logger = createMockLogger();
				const html = render({ uri, state: "s-1" }, logger);

				expect(targetOf(html)).toBeUndefined();
				expect(html).not.toContain("<script");
				expect(html).toContain("<iframe");
				expect(html).not.toContain(uri);
				expect(logger.warn).toHaveBeenCalledTimes(1);
				expectBestEffortWarn(logger, "logout_frontchannel_redirect_refused", { reason }, null);
				expectUriNotLogged(logger, uri);
			},
		);

		it.each([
			[
				"a redirect that is a joined string, not its parts",
				"https://rp.example/out?state=s-1",
				"not-an-object",
			],
			["a base that is not a string", { uri: 42 }, "not-a-string"],
			[
				"a state that is not a string",
				{ uri: "https://rp.example/out", state: 42 },
				"state-not-a-string",
			],
			[
				"a base whose read throws",
				{
					get uri(): string {
						throw new Error("field unavailable");
					},
				},
				"unreadable",
			],
			[
				"a state whose read throws",
				{
					uri: "https://rp.example/out",
					get state(): string {
						throw new Error("field unavailable");
					},
				},
				"unreadable",
			],
		])("refuses %s without throwing", (_label, redirect, reason) => {
			const logger = createMockLogger();
			expect(targetOf(render(redirect, logger))).toBeUndefined();
			expectBestEffortWarn(logger, "logout_frontchannel_redirect_refused", { reason }, null);
		});

		it("refuses a redirect option whose read throws, without throwing", () => {
			const logger = createMockLogger();
			const html = renderFrontchannelLogoutHtml({
				rps: [],
				issuer: "iss",
				sid: "sid",
				logger,
				get postLogoutRedirect(): { uri: string } {
					throw new Error("field unavailable");
				},
			});
			expect(html).not.toContain("<script");
			expectBestEffortWarn(
				logger,
				"logout_frontchannel_redirect_refused",
				{ reason: "unreadable" },
				null,
			);
		});

		it("appends the state with URLSearchParams encoding, leaving the base's scheme, host and path as they are", () => {
			const logger = createMockLogger();
			const state = "a b;c?d&e/f#g@other.example//x";
			const target = targetOf(render({ uri: "https://rp.example/out", state }, logger));

			assert(target !== undefined, "expected the redirect script");
			const url = new URL(target);
			expect(url.origin).toBe("https://rp.example");
			expect(url.pathname).toBe("/out");
			expect(url.hash).toBe("");
			expect([...url.searchParams]).toEqual([["state", state]]);
			expect(target).toBe(
				"https://rp.example/out?state=a+b%3Bc%3Fd%26e%2Ff%23g%40other.example%2F%2Fx",
			);
			expect(logger.warn).not.toHaveBeenCalled();
		});

		it("appends the state after a query the base already has", () => {
			const target = targetOf(
				render({ uri: "https://rp.example/out?tenant=a", state: "s-1" }, createMockLogger()),
			);
			expect(target).toBe("https://rp.example/out?tenant=a&state=s-1");
		});

		it.each([
			["absent", undefined],
			["empty", ""],
		])("writes no state parameter when the state is %s", (_label, state) => {
			const target = targetOf(render({ uri: "https://rp.example/out", state }, createMockLogger()));
			expect(target).toBe("https://rp.example/out");
		});

		it.each([
			["an https base", "https://rp.example/logged-out", "https://rp.example/logged-out?state=s-1"],
			[
				"a reverse-domain custom scheme",
				"com.example.app:/signed-out",
				"com.example.app:/signed-out?state=s-1",
			],
			[
				"plain http on a loopback host",
				"http://127.0.0.1:8080/out",
				"http://127.0.0.1:8080/out?state=s-1",
			],
		])("keeps the redirect for %s, without a warn", (_label, uri, expected) => {
			const logger = createMockLogger();
			expect(targetOf(render({ uri, state: "s-1" }, logger))).toBe(expected);
			expect(logger.warn).not.toHaveBeenCalled();
		});

		it("refuses a base without throwing when the logger throws", () => {
			const logger = createMockLogger();
			logger.warn.mockImplementation(() => {
				throw new Error("logger unavailable");
			});
			expect(targetOf(render({ uri: "ftp://rp.example/out" }, logger))).toBeUndefined();
		});

		it("writes no script and no warn when the redirect or its base is absent", () => {
			const logger = createMockLogger();
			expect(targetOf(render(undefined, logger))).toBeUndefined();
			expect(targetOf(render({ uri: "" }, logger))).toBeUndefined();
			expect(logger.warn).not.toHaveBeenCalled();
		});
	});

	it("postLogoutRedirect cannot close the inline script (CSP-safe pattern)", () => {
		const html = renderFrontchannelLogoutHtml({
			rps: [],
			issuer: "iss",
			sid: "sid",
			postLogoutRedirect: { uri: "https://rp.example/</script><script>x</script>" },
		});
		// The literal </script> must not appear in the output — it would prematurely
		// close the inline <script> block wrapping the redirect. The URL parser
		// percent-encodes it, and the string literal escapes `<` and `>` besides.
		expect(html).not.toContain("</script><script>");
		expect(html).toContain("%3C/script%3E");
	});

	describe("the page's own Content-Security-Policy", () => {
		const page = (
			rps: ReadonlyArray<FrontchannelRP>,
			extra: { postLogoutRedirect?: { uri: string; state?: string }; logger?: MockLogger } = {},
		) =>
			renderFrontchannelLogoutPage({
				rps,
				issuer: "https://auth.example",
				sid: "sid-1",
				logger: extra.logger ?? createMockLogger(),
				...(extra.postLogoutRedirect ? { postLogoutRedirect: extra.postLogoutRedirect } : {}),
			});

		it("returns the same markup renderFrontchannelLogoutHtml does", () => {
			const opts = {
				rps: [{ clientId: "rp", frontchannelLogoutUri: "https://rp.example/fc" }],
				issuer: "https://auth.example",
				sid: "sid-1",
				postLogoutRedirect: { uri: "https://rp.example/out", state: "s-1" },
			};
			expect(renderFrontchannelLogoutPage(opts).html).toBe(renderFrontchannelLogoutHtml(opts));
		});

		it("allows frames from exactly the origins it frames, nothing broader and no wildcard", () => {
			const { html, contentSecurityPolicy } = page([
				{ clientId: "a", frontchannelLogoutUri: "https://rp1.example/fc?tenant=x#r" },
				{ clientId: "b", frontchannelLogoutUri: "https://rp1.example/other" },
				{ clientId: "c", frontchannelLogoutUri: "http://rp2.example:8080/fc" },
				{ clientId: "d", frontchannelLogoutUri: "https://RP3.Example:443/fc" },
				{ clientId: "skipped", frontchannelLogoutUri: "ftp://rp4.example/fc" },
				{ clientId: "none" },
			]);
			const policy = parsePolicy(contentSecurityPolicy);

			const framed = [...new Set(iframeSrcsOf(html).map((src) => new URL(src).origin))];
			expect(framed).toEqual([
				"https://rp1.example",
				"http://rp2.example:8080",
				"https://rp3.example",
			]);
			expect([...(policy.get("frame-src") ?? [])].sort()).toEqual([...framed].sort());
			expect(contentSecurityPolicy).not.toContain("*");
			expect(contentSecurityPolicy).not.toContain("rp4.example");
		});

		it("denies everything else: default-src, base-uri, form-action and frame-ancestors are 'none'", () => {
			const policy = parsePolicy(
				page([{ clientId: "rp", frontchannelLogoutUri: "https://rp.example/fc" }])
					.contentSecurityPolicy,
			);
			expect(policy.get("default-src")).toEqual(["'none'"]);
			expect(policy.get("base-uri")).toEqual(["'none'"]);
			expect(policy.get("form-action")).toEqual(["'none'"]);
			expect(policy.get("frame-ancestors")).toEqual(["'none'"]);
			expect(effectiveSources(policy, "script-src")).toEqual(["'none'"]);
			expect(effectiveSources(policy, "style-src")).toEqual(["'none'"]);
		});

		it("allows no frame when it frames no relying party", () => {
			const { html, contentSecurityPolicy } = page([
				{ clientId: "skipped", frontchannelLogoutUri: "ftp://rp.example/fc" },
			]);
			const policy = parsePolicy(contentSecurityPolicy);

			expect(iframeSrcsOf(html)).toEqual([]);
			expect(policy.has("frame-src")).toBe(false);
			expect(policy.has("child-src")).toBe(false);
			expect(effectiveSources(policy, "frame-src")).toEqual(["'none'"]);
		});

		it("hides its frames with the hidden attribute, which no style-src governs", () => {
			const { html } = page([{ clientId: "rp", frontchannelLogoutUri: "https://rp.example/fc" }]);
			expect(html).toMatch(
				/<iframe src="[^"]*" hidden aria-hidden="true" referrerpolicy="no-referrer"><\/iframe>/,
			);
			expect(html).not.toContain("style=");
		});

		it("skips, with one warn, an RP whose origin a source expression cannot name, and does not allow it", () => {
			const logger = createMockLogger();
			const { html, contentSecurityPolicy } = page(
				[
					{ clientId: "good", frontchannelLogoutUri: "https://good.example/fc" },
					{ clientId: "ipv6", frontchannelLogoutUri: "https://[::1]:8443/fc" },
					{ clientId: "underscore", frontchannelLogoutUri: "https://rp_fc.example/fc" },
					{ clientId: "semicolon", frontchannelLogoutUri: "https://a;script-src/fc" },
				],
				{ logger },
			);

			expect(iframeSrcsOf(html).map((src) => new URL(src).origin)).toEqual([
				"https://good.example",
			]);
			const policy = parsePolicy(contentSecurityPolicy);
			expect(policy.get("frame-src")).toEqual(["https://good.example"]);
			expect(policy.has("script-src")).toBe(false);
			for (const clientId of ["ipv6", "underscore", "semicolon"]) {
				expectBestEffortWarn(
					logger,
					"logout_frontchannel_iframe_skipped",
					{ clientId, reason: "origin-not-a-source-expression" },
					null,
				);
			}
		});

		it("leaves renderFrontchannelLogoutHtml, which carries no policy, rendering those RPs' frames", () => {
			const logger = createMockLogger();
			const html = renderFrontchannelLogoutHtml({
				rps: [
					{ clientId: "ipv6", frontchannelLogoutUri: "https://[::1]:8443/fc" },
					{ clientId: "underscore", frontchannelLogoutUri: "https://rp_fc.example/fc" },
				],
				issuer: "https://auth.example",
				sid: "sid-1",
				logger,
			});

			expect(iframeSrcsOf(html).map((src) => new URL(src).origin)).toEqual([
				"https://[::1]:8443",
				"https://rp_fc.example",
			]);
			expect(logger.warn).not.toHaveBeenCalled();
		});

		describe("the redirect runs under the policy", () => {
			it("allows its one static script by hash, and the script reads the target from its own data attribute", () => {
				const { html, contentSecurityPolicy } = page(
					[{ clientId: "rp", frontchannelLogoutUri: "https://rp.example/fc" }],
					{ postLogoutRedirect: { uri: "https://rp.example/out", state: "s-1" } },
				);
				const scripts = scriptsOf(html);
				expect(scripts).toHaveLength(1);
				const [script] = scripts;
				assert(script !== undefined);
				expect(script.attributes["data-target"]).toBe("https://rp.example/out?state=s-1");
				expect(script.attributes["data-delay"]).toBe("2000");
				expect(script.text).toContain("dataset.target");
				expect(script.text).not.toContain("rp.example");

				const policy = parsePolicy(contentSecurityPolicy);
				expect(policy.get("script-src")).toEqual([hashSourceOf(script.text)]);
			});

			it("emits the same script text, so the same hash, whatever the target and delay", () => {
				const textOf = (uri: string, redirectDelayMs: number): string => {
					const { html } = renderFrontchannelLogoutPage({
						rps: [],
						issuer: "iss",
						sid: "sid",
						postLogoutRedirect: { uri },
						redirectDelayMs,
					});
					return scriptsOf(html)[0]?.text ?? "";
				};
				expect(textOf("https://a.example/out", 0)).toBe(textOf("https://b.example/x?y=1", 5000));
				expect(textOf("https://a.example/out", 0)).not.toBe("");
			});

			it("has no script and allows none without a redirect", () => {
				const { html, contentSecurityPolicy } = page([
					{ clientId: "rp", frontchannelLogoutUri: "https://rp.example/fc" },
				]);
				expect(scriptsOf(html)).toEqual([]);
				expect(html).not.toContain("<script");
				expect(effectiveSources(parsePolicy(contentSecurityPolicy), "script-src")).toEqual([
					"'none'",
				]);
			});

			it.each([
				[
					"a single quote and an ampersand in the path and query",
					"https://rp.example/a'b&c/out?x=1&y='2'",
					"q\"<>'&",
				],
				[
					"a closing script tag in the path",
					"https://rp.example/</script><script>x()</script>",
					"",
				],
				["a double quote in the path", 'https://rp.example/a"onload="x()', "s"],
			])(
				"writes a target with %s into the attribute so it decodes to the target and cannot break out",
				(_label, uri, state) => {
					const { html, contentSecurityPolicy } = page([], {
						postLogoutRedirect: { uri, state },
					});
					const expected = new URL(uri);
					if (state.length > 0) expected.searchParams.set("state", state);

					const scripts = scriptsOf(html);
					expect(scripts).toHaveLength(1);
					expect(scripts[0]?.attributes["data-target"]).toBe(expected.toString());
					expect(Object.keys(scripts[0]?.attributes ?? {}).sort()).toEqual([
						"data-delay",
						"data-target",
					]);
					expect(parsePolicy(contentSecurityPolicy).get("script-src")).toEqual([
						hashSourceOf(scripts[0]?.text ?? ""),
					]);
					expect(html.match(/<script/g)).toHaveLength(1);
				},
			);
		});
	});
});
