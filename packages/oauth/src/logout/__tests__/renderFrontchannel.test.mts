import { assert, describe, expect, it } from "vitest";
import { createMockLogger, type MockLogger } from "../../__tests__/_helpers/mockLogger.mjs";
import {
	expectBestEffortWarn,
	expectUriNotLogged,
} from "../../__tests__/_helpers/projectedLog.mjs";
import { type FrontchannelRP, renderFrontchannelLogoutHtml } from "../renderFrontchannel.mjs";

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

	it("redirects to postLogoutRedirectUri via setTimeout when provided", () => {
		const html = renderFrontchannelLogoutHtml({
			rps: [],
			issuer: "iss",
			sid: "sid",
			postLogoutRedirectUri: "https://rp.example/logged-out",
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
			postLogoutRedirectUri: "https://rp.example/logged-out",
			redirectDelayMs: 500,
		});
		expect(html).toContain(", 500)");
	});

	it("no redirect script when postLogoutRedirectUri is absent", () => {
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
			// The whole tag: a src that ended early would not be followed by ` style=`.
			const match = html.match(
				/<iframe src="([^"]*)" style="display:none" aria-hidden="true" referrerpolicy="no-referrer"><\/iframe>/,
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
				postLogoutRedirectUri: "https://rp.example/logged-out",
				redirectDelayMs,
			});
			const match = html.match(/\}, ([^)]*)\);<\/script>/);
			assert(match !== null, "expected the redirect script");
			return match[1] ?? "";
		};

		it.each([
			["NaN", Number.NaN, "2000"],
			["Infinity", Number.POSITIVE_INFINITY, "2000"],
			["a negative number", -5, "2000"],
			["a fraction", 1500.7, "1500"],
			["a value that is not a number", "soon" as unknown as number, "2000"],
			["zero", 0, "0"],
		])("writes %s into the script as a whole number", (_label, value, expected) => {
			expect(delayIn(value)).toBe(expected);
		});
	});

	describe("postLogoutRedirectUri is held to the redirect-URI rules", () => {
		const scriptFor = (
			postLogoutRedirectUri: unknown,
			logger: MockLogger,
		): { html: string; hasScript: boolean } => {
			const html = renderFrontchannelLogoutHtml({
				rps: [{ clientId: "rp", frontchannelLogoutUri: "https://rp.example/fc" }],
				issuer: "https://auth.example",
				sid: "sid-1",
				postLogoutRedirectUri: postLogoutRedirectUri as string,
				logger,
			});
			return { html, hasScript: html.includes("<script>") };
		};

		it.each([
			["a non-http(s) scheme", "data:text/plain,signed-out", "executable-scheme"],
			["a scheme that is not reverse-domain", "ftp://rp.example/out", "scheme-not-reverse-domain"],
			["plain http off a loopback host", "http://rp.example/out", "http-non-loopback"],
			["a value that is not a URL", "not-a-url", "unparsable"],
		])(
			"refuses %s: the page keeps its iframes, has no redirect script, and one warn names the reason, never the URI",
			(_label, uri, reason) => {
				const logger = createMockLogger();
				const { html, hasScript } = scriptFor(uri, logger);

				expect(hasScript).toBe(false);
				expect(html).toContain("<iframe");
				expect(html).not.toContain(uri);
				expect(logger.warn).toHaveBeenCalledTimes(1);
				expectBestEffortWarn(logger, "logout_frontchannel_redirect_refused", { reason }, null);
				expectUriNotLogged(logger, uri);
			},
		);

		it("refuses a value that is not a string, and a read that throws, without throwing", () => {
			const logger = createMockLogger();
			expect(scriptFor(42, logger).hasScript).toBe(false);
			const throwing = {
				rps: [],
				issuer: "iss",
				sid: "sid",
				logger,
				get postLogoutRedirectUri(): string {
					throw new Error("field unavailable");
				},
			};
			expect(renderFrontchannelLogoutHtml(throwing)).not.toContain("<script>");
			expectBestEffortWarn(
				logger,
				"logout_frontchannel_redirect_refused",
				{ reason: "not-a-string" },
				null,
			);
			expectBestEffortWarn(
				logger,
				"logout_frontchannel_redirect_refused",
				{ reason: "unreadable" },
				null,
			);
		});

		it.each([
			["an https URI", "https://rp.example/logged-out"],
			["an https URI carrying the RP's state", "https://rp.example/logged-out?state=s-1"],
			["a reverse-domain custom scheme", "com.example.app:/signed-out?state=s-1"],
			["plain http on a loopback host", "http://127.0.0.1:8080/out"],
		])("keeps the redirect script for %s, without a warn", (_label, uri) => {
			const logger = createMockLogger();
			const { html, hasScript } = scriptFor(uri, logger);
			expect(hasScript).toBe(true);
			expect(html).toContain(JSON.stringify(uri));
			expect(logger.warn).not.toHaveBeenCalled();
		});

		it.each([
			["a state carrying a semicolon", "https://rp.example/out?state=x;code=y"],
			["a state carrying a newline", "https://rp.example/out?state=x\n"],
			["an empty pair before the state", "https://rp.example/out?&state=x"],
			["an empty pair after the state", "https://rp.example/out?state=x&"],
			["two state parameters", "https://rp.example/out?state=x&state=y"],
			["a state carrying a question mark", "https://rp.example/out?state=x?code=y"],
			["a state with no value", "https://rp.example/out?state"],
			["a state pair outside the query (in the host)", "http://localhost&state=x"],
			["a state pair outside the query (after the port)", "https://rp.example:443&state=x"],
		])("sets aside only a state the logout route writes: refuses %s", (_label, uri) => {
			const logger = createMockLogger();
			const { hasScript } = scriptFor(uri, logger);
			expect(hasScript).toBe(false);
			expect(
				logger.warn.mock.calls.filter(
					([, name]) => name === "logout_frontchannel_redirect_refused",
				),
			).toHaveLength(1);
		});

		it("keeps the state the logout route writes on a registered path that ends in an ampersand", () => {
			const logger = createMockLogger();
			const url = new URL("https://rp.example/out&");
			url.searchParams.set("state", "s-1");
			expect(scriptFor(url.toString(), logger).hasScript).toBe(true);
			expect(logger.warn).not.toHaveBeenCalled();
		});

		it("keeps the state the logout route writes, percent-encoded and with a plus for a space", () => {
			const logger = createMockLogger();
			const url = new URL("https://rp.example/out?tenant=a");
			url.searchParams.set("state", "a b;c?d&e/f");
			const { hasScript } = scriptFor(url.toString(), logger);
			expect(hasScript).toBe(true);
			expect(logger.warn).not.toHaveBeenCalled();
		});

		it("refuses a value without throwing when the logger throws", () => {
			const logger = createMockLogger();
			logger.warn.mockImplementation(() => {
				throw new Error("logger unavailable");
			});
			expect(scriptFor("ftp://rp.example/out", logger).hasScript).toBe(false);
		});

		it("writes no script and no warn when the value is absent", () => {
			const logger = createMockLogger();
			expect(scriptFor(undefined, logger).hasScript).toBe(false);
			expect(scriptFor("", logger).hasScript).toBe(false);
			expect(logger.warn).not.toHaveBeenCalled();
		});
	});

	it("postLogoutRedirectUri is safe against </script> injection (CSP-safe pattern)", () => {
		const html = renderFrontchannelLogoutHtml({
			rps: [],
			issuer: "iss",
			sid: "sid",
			postLogoutRedirectUri: "https://evil.example/</script><script>alert(1)</script>",
		});
		// The literal </script> must not appear in the output — it would prematurely
		// close the inline <script> block wrapping the redirect.
		expect(html).not.toContain("</script><script>");
		// The escaped form (\u003c/script\u003e) is what we expect instead.
		expect(html).toContain("\\u003c/script");
	});
});
