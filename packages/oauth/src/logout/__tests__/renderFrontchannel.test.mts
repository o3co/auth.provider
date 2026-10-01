import { assert, describe, expect, it } from "vitest";
import { createMockLogger, type MockLogger } from "../../__tests__/_helpers/mockLogger.mjs";
import { expectBestEffortWarn, serialisedCalls } from "../../__tests__/_helpers/projectedLog.mjs";
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
		// good RP still produces an iframe
		expect(html).toContain("good.example");
		// bad RP is skipped
		expect(html).not.toContain("bad.example");
		// exactly one iframe in the output
		expect([...html.matchAll(/<iframe/g)].length).toBe(1);
		// one structured warning for the bad RP, with the error's projection
		expectBestEffortWarn(
			logger,
			"logout_frontchannel_iframe_skipped",
			{ clientId: "bad" },
			"TypeError",
		);
	});

	describe("a frontchannelLogoutUri held to the redirect-URI rules", () => {
		const render = (rps: ReadonlyArray<FrontchannelRP>, logger: MockLogger): string =>
			renderFrontchannelLogoutHtml({
				rps: [{ clientId: "good", frontchannelLogoutUri: "https://good.example/fc" }, ...rps],
				issuer: "https://auth.example",
				sid: "sid-1",
				logger,
			});
		const iframeCount = (html: string): number => [...html.matchAll(/<iframe/g)].length;

		it.each([
			["a non-http(s) scheme", "ftp://rp.example/fc", "scheme-not-reverse-domain"],
			["an executable scheme", "data:text/plain,signed-out", "executable-scheme"],
			["plain http off a loopback host", "http://rp.example/fc", "http-non-loopback"],
			["a fragment", "https://rp.example/fc#app-route", "fragment"],
			["userinfo", "https://user@rp.example/fc", "userinfo"],
			["a value that is not a URL", "not-a-url", "unparsable"],
		])(
			"refuses %s: never rendered, the other RPs are, and one warn names the reason, never the URI",
			(_label, uri, reason) => {
				const logger = createMockLogger();
				const html = render([{ clientId: "rp", frontchannelLogoutUri: uri }], logger);

				expect(iframeCount(html)).toBe(1);
				expect(html).toContain("good.example");
				expect(html).not.toContain("rp.example");
				expect(html).not.toContain(uri);
				// Warned once: refused before an iframe URL is built.
				expect(logger.warn).toHaveBeenCalledTimes(1);
				expectBestEffortWarn(
					logger,
					"logout_frontchannel_uri_refused",
					{ site: "logout", clientId: "rp", reason },
					null,
				);
				expect(serialisedCalls(logger)).not.toContain(uri);
			},
		);

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

			expect(iframeCount(html)).toBe(1);
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

		it("renders a loopback http URI and skips an absent one, without a warn", () => {
			const logger = createMockLogger();
			const html = render(
				[
					{ clientId: "loopback", frontchannelLogoutUri: "http://127.0.0.1:8080/fc" },
					{ clientId: "null", frontchannelLogoutUri: null as unknown as string },
					{ clientId: "empty", frontchannelLogoutUri: "" },
					{ clientId: "none" },
				],
				logger,
			);

			expect(iframeCount(html)).toBe(2);
			expect(html).toContain("http://127.0.0.1:8080/fc?iss=");
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
