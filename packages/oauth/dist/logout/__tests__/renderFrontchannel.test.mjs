import { assert, describe, expect, it, vi } from "vitest";
import { renderFrontchannelLogoutHtml } from "../renderFrontchannel.mjs";
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
        expect(html).toMatch(/https:\/\/rp\.example\/fc\?iss=https%3A%2F%2Fauth\.example(?:&|&amp;)sid=sid-1/);
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
        const logger = { warn: vi.fn() };
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
        // warning was logged for the bad RP
        expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining("bad"), expect.anything());
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
