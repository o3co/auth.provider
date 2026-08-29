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
import { describe, expect, it } from "vitest";
import {
	createFederationRedirectPolicy,
	describeRedirectRejection,
	isLoopbackHostname,
	type RedirectRejection,
} from "../redirect-policy.mjs";

const baseConfig = {
	sessionDomain: "example.com",
	authCallbackUrl: "https://app.example.com/auth/callback",
	clientUrl: "https://app.example.com",
	redirectAllowlist: ["https://app.example.com/dashboard", "https://sub.example.com/page"],
};

/** Pulls the machine-readable `(reason: …)` token out of an errorDescription. */
function reasonOf(description: string): string | undefined {
	return /\(reason: ([a-z-]+)\)/.exec(description)?.[1];
}

describe("createFederationRedirectPolicy — validateRedirect exact-match allowlist", () => {
	it("accepts a URL that exactly matches an allowlist entry", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		expect(policy.validateRedirect("https://app.example.com/dashboard").ok).toBe(true);
	});

	it("accepts every entry in the allowlist, not only the first", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		expect(policy.validateRedirect("https://sub.example.com/page").ok).toBe(true);
	});

	it("rejects a URL on a different domain", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		const result = policy.validateRedirect("https://evil.com/steal");
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.status).toBe(400);
			expect(result.error).toBe("invalid_redirect");
			expect(reasonOf(result.errorDescription)).toBe("not-allowlisted");
		}
	});

	it("rejects a sibling path on an allowlisted host — the match is per-URL, not per-host", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		const result = policy.validateRedirect("https://app.example.com/admin");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("not-allowlisted");
	});

	it("rejects an unlisted subdomain of the session domain", () => {
		// Pre-#278 this passed: `sessionDomain` alone admitted every subdomain.
		const policy = createFederationRedirectPolicy(baseConfig);
		const result = policy.validateRedirect("https://other.example.com/page");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("not-allowlisted");
	});

	it("rejects an allowlisted URL that grew a query string", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		const result = policy.validateRedirect("https://app.example.com/dashboard?next=//evil.com");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("not-allowlisted");
	});

	it("rejects an allowlisted URL that grew a fragment", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		const result = policy.validateRedirect("https://app.example.com/dashboard#x");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("not-allowlisted");
	});

	it("rejects a trailing-slash variant of an allowlist entry", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		const result = policy.validateRedirect("https://app.example.com/dashboard/");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("not-allowlisted");
	});

	it("compares normalized paths, so a `..` spelling of an entry still matches", () => {
		// WHATWG parsing collapses `..` before the comparison. Pinned because the
		// alternative — comparing raw strings — would make every equivalent
		// spelling a rejection, and operators would widen the allowlist to
		// compensate.
		const policy = createFederationRedirectPolicy(baseConfig);
		expect(policy.validateRedirect("https://app.example.com/x/../dashboard").ok).toBe(true);
	});

	it("treats host case and the default port as insignificant", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		expect(policy.validateRedirect("https://APP.Example.COM:443/dashboard").ok).toBe(true);
	});

	it("rejects a userinfo-prefixed lookalike host", () => {
		// `https://app.example.com@evil.com/` parses with host `evil.com`.
		const policy = createFederationRedirectPolicy(baseConfig);
		const result = policy.validateRedirect("https://app.example.com@evil.com/dashboard");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("has-credentials");
	});
});

describe("createFederationRedirectPolicy — fail closed without an allowlist", () => {
	it("rejects every URL when no allowlist is configured", () => {
		const policy = createFederationRedirectPolicy({
			authCallbackUrl: "https://app.example.com/auth/callback",
			clientUrl: "https://app.example.com",
		});
		const result = policy.validateRedirect("https://anywhere.example.org/page");
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.status).toBe(400);
			expect(result.error).toBe("invalid_redirect");
			expect(reasonOf(result.errorDescription)).toBe("no-allowlist");
		}
	});

	it("rejects a URL on the session domain when no allowlist is configured", () => {
		const policy = createFederationRedirectPolicy({ sessionDomain: "example.com" });
		const result = policy.validateRedirect("https://example.com/dashboard");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("no-allowlist");
	});

	it("treats an explicitly empty allowlist the same as an absent one", () => {
		const policy = createFederationRedirectPolicy({ redirectAllowlist: [] });
		const result = policy.validateRedirect("https://app.example.com/dashboard");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("no-allowlist");
	});
});

describe("createFederationRedirectPolicy — validateRedirect shape rules", () => {
	const policy = createFederationRedirectPolicy(baseConfig);

	it("rejects a URL that exceeds 2048 characters before parsing it", () => {
		const result = policy.validateRedirect(`https://app.example.com/${"x".repeat(2100)}`);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.status).toBe(400);
			expect(reasonOf(result.errorDescription)).toBe("too-long");
		}
	});

	it("rejects a non-http/https scheme", () => {
		const result = policy.validateRedirect("ftp://app.example.com/file");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("unsupported-scheme");
	});

	it("rejects `javascript:alert(1)` as not-absolute-url — it never reaches the scheme check", () => {
		// Bare `javascript:` has no `scheme://`, so the absolute-URL gate refuses
		// it first and the scheme check never sees it. Asserting the syntactic
		// reason is honest about which gate fires; the property that a script
		// payload cannot become a redirect target is pinned separately below,
		// across both gates, so it survives either one being rewritten.
		const result = policy.validateRedirect("javascript:alert(1)");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("not-absolute-url");
	});

	it("rejects `javascript://…` as unsupported-scheme — this spelling does reach the scheme check", () => {
		// `javascript://evil.com/%0aalert(1)` carries the `://` the bare form
		// lacks, so it parses with protocol `javascript:` and is refused by the
		// scheme check itself. The `//` comments out the host to a JS engine and
		// `%0a` starts the payload on the next line — the reason this spelling
		// exists at all.
		const result = policy.validateRedirect("javascript://evil.com/%0aalert(1)");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("unsupported-scheme");
	});

	it("refuses every script-bearing scheme, whichever gate catches it", () => {
		// The security property, stated without naming a gate: none of these can
		// become a redirect target. Deliberately asserts only the refusal, so a
		// change to which check fires first cannot quietly turn one of these into
		// an accepted URL while the reason-specific tests above go on passing.
		const payloads = [
			"javascript:alert(1)",
			"javascript://evil.com/%0aalert(1)",
			"JavaScript://evil.com/%0aalert(1)",
			"data:text/html,<script>alert(1)</script>",
			"data://evil.com/x",
			"vbscript:msgbox(1)",
			"file:///etc/passwd",
		];
		for (const payload of payloads) {
			expect(policy.validateRedirect(payload).ok, payload).toBe(false);
		}
	});

	it("rejects a relative path", () => {
		const result = policy.validateRedirect("/dashboard");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("not-absolute-url");
	});

	it("rejects a protocol-relative URL", () => {
		const result = policy.validateRedirect("//evil.com/steal");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("not-absolute-url");
	});

	it("rejects the empty string", () => {
		const result = policy.validateRedirect("");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("empty");
	});

	it("rejects a non-string, defensively", () => {
		const result = policy.validateRedirect(undefined as unknown as string);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("not-a-string");
	});

	it("rejects the http twin of an https entry as insecure-scheme, before the allowlist", () => {
		// The scheme gate runs ahead of membership, so downgrading an allowlisted
		// https target to http is reported as the scheme problem it is rather
		// than as a missing entry — which would read like "add it to the list".
		const httpPolicy = createFederationRedirectPolicy({
			redirectAllowlist: ["https://app.example.com/dashboard"],
		});
		const result = httpPolicy.validateRedirect("http://app.example.com/dashboard");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("insecure-scheme");
	});
});

describe("createFederationRedirectPolicy — loopback carve-out", () => {
	it("accepts an http loopback entry by name", () => {
		const policy = createFederationRedirectPolicy({
			redirectAllowlist: ["http://localhost:3000/welcome"],
		});
		expect(policy.validateRedirect("http://localhost:3000/welcome").ok).toBe(true);
	});

	it("accepts an http loopback entry anywhere in 127.0.0.0/8", () => {
		const policy = createFederationRedirectPolicy({
			redirectAllowlist: ["http://127.0.0.53:8080/cb"],
		});
		expect(policy.validateRedirect("http://127.0.0.53:8080/cb").ok).toBe(true);
	});

	it("accepts an http IPv6 loopback entry", () => {
		const policy = createFederationRedirectPolicy({
			redirectAllowlist: ["http://[::1]:8080/cb"],
		});
		expect(policy.validateRedirect("http://[::1]:8080/cb").ok).toBe(true);
	});

	it("keeps the port significant — a loopback entry is not port-agnostic", () => {
		const policy = createFederationRedirectPolicy({
			redirectAllowlist: ["http://127.0.0.1:3000/cb"],
		});
		const result = policy.validateRedirect("http://127.0.0.1:5173/cb");
		expect(result.ok).toBe(false);
		if (!result.ok) expect(reasonOf(result.errorDescription)).toBe("not-allowlisted");
	});

	it("permits a loopback entry even when sessionDomain narrows everything else", () => {
		const policy = createFederationRedirectPolicy({
			sessionDomain: ".example.com",
			redirectAllowlist: ["https://app.example.com/dashboard", "http://localhost:5173/welcome"],
		});
		expect(policy.validateRedirect("http://localhost:5173/welcome").ok).toBe(true);
	});

	it("does not treat a private-range address as loopback", () => {
		expect(isLoopbackHostname("10.0.0.5")).toBe(false);
		expect(isLoopbackHostname("192.168.1.1")).toBe(false);
		expect(isLoopbackHostname("localhost.evil.com")).toBe(false);
		expect(isLoopbackHostname("127.0.0.1")).toBe(true);
		expect(isLoopbackHostname("127.0.0.53")).toBe(true);
		expect(isLoopbackHostname("localhost")).toBe(true);
		expect(isLoopbackHostname("[::1]")).toBe(true);
	});
});

describe("createFederationRedirectPolicy — allowlist entries are validated at construction", () => {
	it("throws on an entry that is not an absolute URL", () => {
		expect(() => createFederationRedirectPolicy({ redirectAllowlist: ["/dashboard"] })).toThrow(
			/redirectAllowlist\[0\].*not-absolute-url/s,
		);
	});

	it("throws on a non-loopback http entry", () => {
		expect(() =>
			createFederationRedirectPolicy({
				redirectAllowlist: ["https://app.example.com/a", "http://app.example.com/b"],
			}),
		).toThrow(/redirectAllowlist\[1\].*insecure-scheme/s);
	});

	it("throws on an entry embedding credentials", () => {
		expect(() =>
			createFederationRedirectPolicy({
				redirectAllowlist: ["https://user:pw@app.example.com/a"],
			}),
		).toThrow(/redirectAllowlist\[0\].*has-credentials/s);
	});

	it("throws on an entry outside a configured sessionDomain", () => {
		expect(() =>
			createFederationRedirectPolicy({
				sessionDomain: "example.com",
				redirectAllowlist: ["https://partner.example.org/landing"],
			}),
		).toThrow(/redirectAllowlist\[0\].*outside-session-domain/s);
	});

	it("accepts an entry on a subdomain of a leading-dot sessionDomain", () => {
		expect(() =>
			createFederationRedirectPolicy({
				sessionDomain: ".example.com",
				redirectAllowlist: ["https://app.example.com/a"],
			}),
		).not.toThrow();
	});

	it("does not echo the rejected entry, which may embed a secret", () => {
		let message = "";
		try {
			createFederationRedirectPolicy({
				redirectAllowlist: ["https://user:hunter2@app.example.com/a"],
			});
		} catch (err) {
			message = (err as Error).message;
		}
		expect(message).not.toBe("");
		expect(message).not.toMatch(/hunter2/);
	});

	it("throws when an entry is not a string", () => {
		expect(() =>
			createFederationRedirectPolicy({
				redirectAllowlist: [42] as unknown as readonly string[],
			}),
		).toThrow(/redirectAllowlist\[0\].*not-a-string/s);
	});

	it("throws when the allowlist is not an array at all", () => {
		// A separate guard from the per-entry one above, and separately covered:
		// `redirectAllowlist = "https://app.example.com/x"` is the natural typo,
		// and a bare string is iterable, so without this guard it would be walked
		// character by character rather than refused.
		expect(() =>
			createFederationRedirectPolicy({
				redirectAllowlist: "https://app.example.com/x" as unknown as readonly string[],
			}),
		).toThrow(/redirectAllowlist must be an array/);
	});

	it("is not retroactively widened by mutating the caller's array", () => {
		const allowlist = ["https://app.example.com/dashboard"];
		const policy = createFederationRedirectPolicy({ redirectAllowlist: allowlist });
		allowlist.push("https://evil.com/steal");
		expect(policy.validateRedirect("https://evil.com/steal").ok).toBe(false);
	});
});

describe("describeRedirectRejection", () => {
	const reasons: readonly RedirectRejection[] = [
		"not-a-string",
		"empty",
		"too-long",
		"not-absolute-url",
		"unsupported-scheme",
		"insecure-scheme",
		"has-credentials",
		"outside-session-domain",
		"no-allowlist",
		"not-allowlisted",
	];

	it("has a non-empty explanation for every reason", () => {
		for (const reason of reasons) {
			expect(describeRedirectRejection(reason).length).toBeGreaterThan(0);
		}
	});

	it("names the loopback carve-out in both scheme messages", () => {
		expect(describeRedirectRejection("unsupported-scheme")).toMatch(/loopback/);
		expect(describeRedirectRejection("insecure-scheme")).toMatch(/loopback/);
	});

	/*
	 * #405 — the same rule now guards two entry points configured in two
	 * places, so the two allowlist reasons have to name the caller's own key.
	 * A login-flow operator sent to `federations.<name>.redirectAllowlist`
	 * edits a section that has no effect on the request they are debugging.
	 */
	it("names the caller's allowlist config key in the two allowlist reasons", () => {
		const withKey = { allowlistConfigKey: "session.redirectAllowlist" };
		expect(describeRedirectRejection("no-allowlist", withKey)).toContain(
			"session.redirectAllowlist",
		);
		expect(describeRedirectRejection("not-allowlisted", withKey)).toContain(
			"session.redirectAllowlist",
		);
	});

	it("defaults to naming the federation's allowlist, which is what the federation policy builds", () => {
		expect(describeRedirectRejection("no-allowlist")).toContain("federation");
		expect(describeRedirectRejection("not-allowlisted")).toContain("federation");
	});

	it("leaves the shape reasons free of any config key", () => {
		const withKey = { allowlistConfigKey: "session.redirectAllowlist" };
		for (const reason of reasons.filter((r) => r !== "no-allowlist" && r !== "not-allowlisted")) {
			expect(describeRedirectRejection(reason, withKey)).toBe(describeRedirectRejection(reason));
		}
	});
});

describe("createFederationRedirectPolicy — resolveCallbackRedirect", () => {
	it("returns authCallbackUrl?redirect_to=<encoded> when session has redirectTo", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		const redirectTo = "https://app.example.com/dashboard";
		const result = policy.resolveCallbackRedirect({ redirectTo });
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value).toBe(
				`https://app.example.com/auth/callback?redirect_to=${encodeURIComponent(redirectTo)}`,
			);
		}
	});

	it("returns clientUrl fallback when session has no redirectTo", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		const result = policy.resolveCallbackRedirect({});
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value).toBe("https://app.example.com");
		}
	});

	it("returns misconfiguration error when redirectTo present but authCallbackUrl absent", () => {
		const policy = createFederationRedirectPolicy({
			clientUrl: "https://app.example.com",
		});
		const result = policy.resolveCallbackRedirect({ redirectTo: "https://example.com/x" });
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.status).toBe(500);
			expect(result.error).toBe("misconfiguration");
		}
	});

	it("returns misconfiguration error when no redirectTo and clientUrl absent", () => {
		const policy = createFederationRedirectPolicy({
			authCallbackUrl: "https://app.example.com/auth/callback",
		});
		const result = policy.resolveCallbackRedirect({});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.status).toBe(500);
			expect(result.error).toBe("misconfiguration");
		}
	});
});

describe("createFederationRedirectPolicy — return value is frozen", () => {
	it("returned policy is Object.frozen", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		expect(Object.isFrozen(policy)).toBe(true);
	});
});
