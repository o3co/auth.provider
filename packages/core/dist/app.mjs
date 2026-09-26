import { composeConfigSchema } from "./config/application.schema.mjs";
import { GrantRegistry } from "./grants/registry.mjs";
import * as healthcheck from "./routes/Healthcheck.mjs";
import * as jwks from "./routes/Jwks.mjs";
export function createApp(options) {
    const { pathResolver = (s) => s, config, keyStore, modules } = options;
    if (options.mfaCoordinator) {
        if (!options.mfaProviderFactory) {
            throw new Error("createApp: mfaProviderFactory is required when mfaCoordinator is set");
        }
        if (!options.mfaTransactionStore) {
            throw new Error("createApp: mfaTransactionStore is required when mfaCoordinator is set");
        }
    }
    // Spec Section 10.1 — federations configured means stores are required.
    // This runs BEFORE zod parsing, so `enabled` may still be a string from
    // env-var overrides (HOCON substitutions emit `"true"`/`"1"`). We MUST
    // accept exactly the strings that Plan #3's `coerceBooleanFromEnv`
    // zod-preprocess coerces to true, so this pre-parse check neither
    // (a) lets a schema-enabled federation slip through unchecked nor
    // (b) rejects a config that zod would later reject anyway (false
    // positive, mask the real schema error).
    //
    // Matches schema behavior: only `"true"` and `"1"` coerce to true.
    // Arbitrary strings like "yes"/"on" are rejected by the schema, so
    // treating them as truthy here would fire the stores-missing error
    // before the real validation message.
    const isEnabledTruthy = (v) => {
        if (v === true)
            return true;
        if (typeof v !== "string")
            return false;
        const normalized = v.trim().toLowerCase();
        return normalized === "true" || normalized === "1";
    };
    const federationsCfg = config
        .federations;
    const federationsConfigured = typeof federationsCfg === "object" &&
        federationsCfg !== null &&
        Object.values(federationsCfg).some((f) => f != null && isEnabledTruthy(f.enabled));
    if (federationsConfigured && !options.federationTokenStore) {
        throw new Error("createApp: federations are configured but federationTokenStore was not provided. " +
            "Register a FederationTokenStore adapter in AppOptions.");
    }
    if (federationsConfigured && !options.userSessionStore) {
        throw new Error("createApp: federations are configured but userSessionStore was not provided. " +
            "Register a UserSessionStore adapter in AppOptions.");
    }
    // CP-20: when grantPolicy is configured, config.oauth.jwt.issuer MUST be
    // set so the issuer observed by the policy matches the issuer claim on
    // minted tokens. Otherwise policy decisions are made against a different
    // (or empty) issuer than what ends up in the token, which silently
    // splits the two code paths.
    if (options.grantPolicy) {
        const oauth = config.oauth;
        const issuer = oauth?.jwt?.issuer;
        if (typeof issuer !== "string" || issuer.length === 0) {
            throw new Error("createApp: config.oauth.jwt.issuer must be set when grantPolicy is configured (policy evaluations and minted tokens must share a single trusted issuer)");
        }
    }
    const express = options.express ??
        (() => {
            throw new Error("express must be provided in AppOptions or resolved via pathResolver before createApp is called");
        })();
    const router = express.Router();
    const grantRegistry = new GrantRegistry();
    // Wire core infrastructure routes (pure — no external deps)
    router.use(healthcheck.createRouter(express)).use(jwks.createRouter(express, keyStore));
    // OIDC discovery is mounted by the oauth module (when the OAuth endpoints
    // it advertises actually exist). See packages/oauth/src/module.mts.
    const context = {
        pathResolver,
        config,
        keyStore,
        grantRegistry,
        router,
        mfaProviderFactory: options.mfaProviderFactory,
        mfaCoordinator: options.mfaCoordinator,
        mfaTransactionStore: options.mfaTransactionStore,
        auditSink: options.auditSink,
        rateLimiter: options.rateLimiter,
        refreshTokenStore: options.refreshTokenStore,
        grantPolicy: options.grantPolicy,
        userSessionStore: options.userSessionStore,
        federationTokenStore: options.federationTokenStore,
    };
    async function init() {
        const moduleSchemas = modules
            .map((m) => m.configSchema)
            .filter((s) => s !== undefined);
        const validatedConfig = composeConfigSchema(moduleSchemas).parse(config);
        context.config = validatedConfig;
        for (const module of modules) {
            await module.init(context);
        }
    }
    return { init, router, grantRegistry };
}
