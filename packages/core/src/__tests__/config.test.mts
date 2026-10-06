import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { CoreConfigSchema } from "#/config/application.schema.mjs";

describe("provider config", () => {
	it("loads and validates reference.conf with no variable set", () => {
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {},
		});
		validate(raw, CoreConfigSchema);

		// The signing key, the log level, the HTTP settings, the Redis stores'
		// settings and the session's are the sections of the modules that own
		// them, with their defaults in those modules' package: core ships none.
		// `oauth {}` is the oauth module's, its defaults in the oauth package's
		// reference: core sets none of it.
		const sections = raw.toObject() as Record<string, unknown>;
		expect(sections.oauth).toBeUndefined();
		expect(sections["key-store"]).toBeUndefined();
		expect(sections.logging).toBeUndefined();
		expect(sections.http).toBeUndefined();
		// Which adapter fills a slot is the composition root's (`adapters`), the
		// repositories' and the audit sink's settings their modules': core ships
		// none of them.
		for (const section of [
			"audit",
			"repositories",
			"rateLimiter",
			"userSessionStores",
			"accessTokenDenylist",
			"replaySeenSet",
			"consentStore",
			"federationTokenStore",
			"federationGrantStore",
			"federationGrantIntentStore",
			"mfaFactorStore",
			"mfaTransactionStore",
			"redisCodeRepository",
		]) {
			expect(sections[section], section).toBeUndefined();
		}
		expect(sections["redis-session-stores"]).toBeUndefined();
		expect(sections.session).toBeUndefined();
		expect(sections["session-store"]).toBeUndefined();
	});

	it("binds none of the oauth module's variables", () => {
		// An exported OAUTH_* variable reaches oauth {} only through the oauth
		// package's reference, layered when one of its modules is loaded.
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_ISSUER: "https://auth.test",
				OAUTH_OIDC_MODE: "dual",
				OAUTH_REVOCATION_SUBJECT: "unsupported",
				OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS: "false",
			},
		});
		expect((raw.toObject() as Record<string, unknown>).oauth).toBeUndefined();
	});

	it("overrides defaults with env vars", () => {
		const raw = parseFile(new URL("../../config/reference.conf", import.meta.url).pathname, {
			env: { CORE_TOKEN_BINDING_DISPATCH_POLICY: "strict-mutual-exclusion" },
		});
		const config = validate(raw, CoreConfigSchema);

		expect(config.core?.tokenBinding?.dispatchPolicy).toBe("strict-mutual-exclusion");
	});

	it("loads core-rate-limiter-memory.maxBuckets default and CORE_RATE_LIMITER_MEMORY_MAX_BUCKETS", () => {
		const path = new URL("../../config/reference.conf", import.meta.url).pathname;
		// As written: the module's own section schema reads it.
		const base = parseFile(path, {
			env: {},
		}).toObject() as Record<string, unknown>;
		expect(base["core-rate-limiter-memory"]).toMatchObject({ maxBuckets: 10_000 });

		const overridden = parseFile(path, {
			env: { CORE_RATE_LIMITER_MEMORY_MAX_BUCKETS: "123" },
		}).toObject() as Record<string, unknown>;
		expect(overridden["core-rate-limiter-memory"]).toMatchObject({ maxBuckets: "123" });
	});
});
