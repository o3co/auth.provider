import { z } from "zod";
/** `logging`: the level the process logs at. `silent` is a threshold, not a level. */
export declare const loggingSectionSchema: z.ZodObject<{
    level: z.ZodEnum<{
        trace: "trace";
        debug: "debug";
        info: "info";
        warn: "warn";
        error: "error";
        fatal: "fatal";
        silent: "silent";
    }>;
}, z.core.$strict>;
/** What the logger is built from: the `logging` module's section. */
export type LoggingSettings = z.output<typeof loggingSectionSchema>;
/**
 * `http`: the listener's port, the trusted forwarding hops, the readiness
 * deadline, and the CORS list. The deadline is bounded both ways, because
 * `setTimeout` turns 0 and anything above 2^31-1 into 1 ms: every probe would
 * time out.
 */
export declare const httpSectionSchema: z.ZodObject<{
    port: z.ZodPreprocess<z.ZodNumber, unknown>;
    trustProxy: z.ZodPreprocess<z.ZodUnion<readonly [z.ZodBoolean, z.ZodNumber, z.ZodArray<z.ZodString>]>, unknown>;
    readinessTimeoutMs: z.ZodPreprocess<z.ZodNumber, unknown>;
    cors: z.ZodObject<{
        allowedOrigins: z.ZodPreprocess<z.ZodArray<z.ZodString>, unknown>;
    }, z.core.$strict>;
}, z.core.$strict>;
/**
 * `key-store`: which key store builds the signing key (`provider`, `local` the
 * one this template registers) and the local store's settings, shape only:
 * whether the key material is there is the key store's check, when it is
 * built.
 */
export declare const keyStoreSectionSchema: z.ZodObject<{
    provider: z.ZodString;
    local: z.ZodOptional<z.ZodDiscriminatedUnion<[z.ZodObject<{
        algorithm: z.ZodLiteral<"HS256">;
        kid: z.ZodString & z.ZodType<string, string, z.core.$ZodTypeInternals<string, string>>;
        secret: z.ZodOptional<z.ZodString>;
        previousSecrets: z.ZodOptional<z.ZodArray<z.ZodObject<{
            kid: z.ZodString & z.ZodType<string, string, z.core.$ZodTypeInternals<string, string>>;
            secret: z.ZodString;
            expiresAt: z.ZodString;
        }, z.core.$strict>>>;
    }, z.core.$strict>, z.ZodObject<{
        algorithm: z.ZodEnum<{
            RS256: "RS256";
            ES256: "ES256";
            EdDSA: "EdDSA";
        }>;
        kid: z.ZodString & z.ZodType<string, string, z.core.$ZodTypeInternals<string, string>>;
        privateKey: z.ZodOptional<z.ZodString>;
        privateKeyPath: z.ZodOptional<z.ZodString>;
        publicKey: z.ZodOptional<z.ZodString>;
        publicKeyPath: z.ZodOptional<z.ZodString>;
        previousKeys: z.ZodOptional<z.ZodArray<z.ZodObject<{
            kid: z.ZodString & z.ZodType<string, string, z.core.$ZodTypeInternals<string, string>>;
            publicKey: z.ZodOptional<z.ZodString>;
            publicKeyPath: z.ZodOptional<z.ZodString>;
            expiresAt: z.ZodString;
        }, z.core.$strict>>>;
        secret: z.ZodOptional<z.ZodString>;
        previousSecrets: z.ZodOptional<z.ZodUnknown>;
    }, z.core.$strict>], "algorithm">>;
}, z.core.$strict>;
/**
 * `redis-clients`: the one Redis connection every Redis-backed store shares.
 * `assumeNoEviction` is the operator's assertion that the server runs
 * `maxmemory-policy noeviction`, read by the Redis stores' eviction gate only
 * where the server will not report its policy; the template's
 * `config/reference.conf` ships it false.
 */
export declare const redisClientsSectionSchema: z.ZodObject<{
    url: z.ZodString;
    password: z.ZodOptional<z.ZodString>;
    assumeNoEviction: z.ZodPreprocess<z.ZodBoolean, unknown>;
}, z.core.$strict>;
/**
 * `adapters`: which adapter fills each slot, the composition root's own
 * choice. `userSessionStores` switches the four user-session stores and the
 * subject-level revocation pair together; the repositories take core's
 * `static`, an alias of `yaml` with a block of its own; `mfaFactorStore` and
 * `mfaTransactionStore` are read by a composition that installs MFA;
 * `auditSink` names a sink the audit-sink module's factory registers.
 */
export declare const adaptersSchema: z.ZodObject<{
    rateLimiter: z.ZodEnum<{
        memory: "memory";
        redis: "redis";
    }>;
    attemptCounter: z.ZodEnum<{
        memory: "memory";
        redis: "redis";
    }>;
    userSessionStores: z.ZodEnum<{
        memory: "memory";
        redis: "redis";
    }>;
    accessTokenDenylist: z.ZodEnum<{
        memory: "memory";
        redis: "redis";
    }>;
    replaySeenSet: z.ZodEnum<{
        memory: "memory";
        redis: "redis";
    }>;
    consentStore: z.ZodEnum<{
        memory: "memory";
        redis: "redis";
        none: "none";
    }>;
    federationTokenStore: z.ZodEnum<{
        memory: "memory";
        redis: "redis";
    }>;
    federationGrantStore: z.ZodEnum<{
        memory: "memory";
        redis: "redis";
        none: "none";
    }>;
    federationGrantIntentStore: z.ZodEnum<{
        memory: "memory";
        redis: "redis";
        none: "none";
    }>;
    mfaFactorStore: z.ZodEnum<{
        memory: "memory";
        redis: "redis";
        store: "store";
    }>;
    mfaTransactionStore: z.ZodEnum<{
        memory: "memory";
        redis: "redis";
    }>;
    codeRepository: z.ZodEnum<{
        memory: "memory";
        redis: "redis";
    }>;
    clientRepository: z.ZodEnum<{
        yaml: "yaml";
        static: "static";
    }>;
    userRepository: z.ZodEnum<{
        yaml: "yaml";
        static: "static";
        http: "http";
    }>;
    auditSink: z.ZodString;
}, z.core.$strict>;
/** The composition root's adapter selections, as `adaptersSchema` reads them. */
export type Adapters = z.output<typeof adaptersSchema>;
/** A section of keys: an object whose prototype is `Object.prototype` or none. */
export declare function isPlainSection(value: unknown): value is Readonly<Record<string, unknown>>;
/**
 * `mfaMode`: whether the composition root installs MFA, its own choice — the
 * MFA package's mode, read with that package's schema for `mfa.mode`. `off`
 * installs nothing of MFA; `optional` and `required` install it and are
 * written to `mfa.mode`.
 */
export declare const mfaSwitchSchema: z.ZodEnum<{
    required: "required";
    optional: "optional";
    off: "off";
}>;
/** The composition root's MFA switch, as `mfaSwitchSchema` reads it. */
export type MfaSwitch = z.output<typeof mfaSwitchSchema>;
/**
 * `repositories`: the YAML client registry, and the user repository's
 * settings for each adapter it may be — the YAML file, or the Store's HTTP
 * endpoints. `static`, core's alias of `yaml`, reads the same shape from a
 * block of its own, which has no default. The HTTP settings are shape only: the repository holds each
 * value to its rules (https or loopback, a credential's strength, positive
 * whole numbers) when it is built, and names what it refuses.
 */
export declare const repositoriesSectionSchema: z.ZodObject<{
    client: z.ZodObject<{
        yaml: z.ZodObject<{
            path: z.ZodString;
        }, z.core.$strict>;
        static: z.ZodOptional<z.ZodObject<{
            path: z.ZodString;
        }, z.core.$strict>>;
    }, z.core.$strict>;
    user: z.ZodObject<{
        yaml: z.ZodObject<{
            path: z.ZodString;
        }, z.core.$strict>;
        static: z.ZodOptional<z.ZodObject<{
            path: z.ZodString;
        }, z.core.$strict>>;
        http: z.ZodObject<{
            authenticateUrl: z.ZodOptional<z.ZodUnknown>;
            authenticateByTokenUrl: z.ZodOptional<z.ZodUnknown>;
            linkFederatedIdentityUrl: z.ZodOptional<z.ZodUnknown>;
            findSubjectByFederatedIdentityUrl: z.ZodOptional<z.ZodUnknown>;
            markMfaEnrolledUrl: z.ZodOptional<z.ZodUnknown>;
            federatedIdentityLookupCoverage: z.ZodOptional<z.ZodUnknown>;
            bearerToken: z.ZodOptional<z.ZodUnknown>;
            timeout: z.ZodOptional<z.ZodUnknown>;
            maxResponseBytes: z.ZodOptional<z.ZodUnknown>;
        }, z.core.$strict>;
    }, z.core.$strict>;
}, z.core.$strict>;
/**
 * `repositories` for the adapters `selection` names: `repositoriesSectionSchema`,
 * and the `static` block's path required for a repository that selects
 * `static`, since the block has no default. Refused at the section's parse,
 * naming the path, before any repository is built.
 */
export declare function repositoriesSectionSchemaFor(selection: {
    readonly client: Adapters["clientRepository"];
    readonly user: Adapters["userRepository"];
}): z.ZodObject<{
    client: z.ZodObject<{
        yaml: z.ZodObject<{
            path: z.ZodString;
        }, z.core.$strict>;
        static: z.ZodOptional<z.ZodObject<{
            path: z.ZodString;
        }, z.core.$strict>>;
    }, z.core.$strict>;
    user: z.ZodObject<{
        yaml: z.ZodObject<{
            path: z.ZodString;
        }, z.core.$strict>;
        static: z.ZodOptional<z.ZodObject<{
            path: z.ZodString;
        }, z.core.$strict>>;
        http: z.ZodObject<{
            authenticateUrl: z.ZodOptional<z.ZodUnknown>;
            authenticateByTokenUrl: z.ZodOptional<z.ZodUnknown>;
            linkFederatedIdentityUrl: z.ZodOptional<z.ZodUnknown>;
            findSubjectByFederatedIdentityUrl: z.ZodOptional<z.ZodUnknown>;
            markMfaEnrolledUrl: z.ZodOptional<z.ZodUnknown>;
            federatedIdentityLookupCoverage: z.ZodOptional<z.ZodUnknown>;
            bearerToken: z.ZodOptional<z.ZodUnknown>;
            timeout: z.ZodOptional<z.ZodUnknown>;
            maxResponseBytes: z.ZodOptional<z.ZodUnknown>;
        }, z.core.$strict>;
    }, z.core.$strict>;
}, z.core.$strict>;
/** The in-process code repository's section: the default lifetime, in positive whole seconds. */
export declare const inMemoryCodeRepositorySectionSchema: z.ZodObject<{
    defaultExpiresIn: z.ZodPreprocess<z.ZodNumber, unknown>;
}, z.core.$strict>;
/**
 * `audit-sink`: each sink's options, keyed by the sink's name, for the sink
 * `adapters.auditSink` selects. Open: the sinks are the factory's, and each
 * builder holds its own options to its rules.
 */
export declare const auditSinkSectionSchema: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodRecord<z.ZodString, z.ZodUnknown>>>;
//# sourceMappingURL=sections.d.mts.map