import { z } from "zod";
/**
 * Minimal always-required config for the auth provider core.
 * DID-only deployments only need these sections.
 */
export declare const CoreConfigSchema: z.ZodObject<{
    http: z.ZodObject<{
        port: z.ZodDefault<z.ZodCoercedNumber<unknown>>;
        trustProxy: z.ZodDefault<z.ZodBoolean>;
    }, z.core.$strip>;
    oauth: z.ZodObject<{
        jwt: z.ZodPipe<z.ZodTransform<unknown, unknown>, z.ZodObject<{
            issuer: z.ZodOptional<z.ZodString>;
            signingKey: z.ZodDefault<z.ZodObject<{
                provider: z.ZodDefault<z.ZodString>;
                local: z.ZodOptional<z.ZodObject<{
                    algorithm: z.ZodDefault<z.ZodEnum<{
                        HS256: "HS256";
                        RS256: "RS256";
                        ES256: "ES256";
                        EdDSA: "EdDSA";
                    }>>;
                    kid: z.ZodDefault<z.ZodString>;
                    secret: z.ZodOptional<z.ZodString>;
                    privateKey: z.ZodOptional<z.ZodString>;
                    privateKeyPath: z.ZodOptional<z.ZodString>;
                    publicKey: z.ZodOptional<z.ZodString>;
                    publicKeyPath: z.ZodOptional<z.ZodString>;
                    previousKeys: z.ZodDefault<z.ZodArray<z.ZodObject<{
                        kid: z.ZodString;
                        publicKey: z.ZodOptional<z.ZodString>;
                        publicKeyPath: z.ZodOptional<z.ZodString>;
                        expiresAt: z.ZodString;
                    }, z.core.$strip>>>;
                }, z.core.$loose>>;
            }, z.core.$loose>>;
        }, z.core.$strip>>;
        accessToken: z.ZodObject<{
            expiresIn: z.ZodDefault<z.ZodCoercedNumber<unknown>>;
        }, z.core.$strip>;
        refreshToken: z.ZodObject<{
            expiresIn: z.ZodDefault<z.ZodCoercedNumber<unknown>>;
        }, z.core.$strip>;
        grants: z.ZodObject<{}, z.core.$loose>;
    }, z.core.$strip>;
}, z.core.$strip>;
export type CoreConfig = z.infer<typeof CoreConfigSchema>;
/**
 * Composes a config schema by merging module-specific schemas with the CoreConfigSchema.
 * Each module can declare its required config shape; the resulting schema validates
 * the intersection of core + all module schemas.
 */
export declare function composeConfigSchema(moduleSchemas: z.ZodObject<z.ZodRawShape>[]): z.ZodType;
export declare const fullSectionsSchema: z.ZodObject<{
    session: z.ZodObject<{
        secret: z.ZodString;
        maxAge: z.ZodDefault<z.ZodCoercedNumber<unknown>>;
        secure: z.ZodDefault<z.ZodBoolean>;
        sameSite: z.ZodDefault<z.ZodEnum<{
            lax: "lax";
            none: "none";
            strict: "strict";
        }>>;
        domain: z.ZodDefault<z.ZodNullable<z.ZodString>>;
        storage: z.ZodObject<{
            type: z.ZodDefault<z.ZodString>;
            redis: z.ZodOptional<z.ZodObject<{
                url: z.ZodDefault<z.ZodString>;
                password: z.ZodOptional<z.ZodString>;
            }, z.core.$strip>>;
        }, z.core.$loose>;
    }, z.core.$strip>;
    rateLimit: z.ZodObject<{
        login: z.ZodObject<{
            windowMs: z.ZodCoercedNumber<unknown>;
            limit: z.ZodCoercedNumber<unknown>;
        }, z.core.$strip>;
    }, z.core.$strip>;
    federations: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodObject<{
        enabled: z.ZodPipe<z.ZodTransform<unknown, unknown>, z.ZodDefault<z.ZodBoolean>>;
        type: z.ZodOptional<z.ZodString>;
    }, z.core.$loose>>>;
    repositories: z.ZodObject<{
        client: z.ZodObject<{
            type: z.ZodDefault<z.ZodString>;
        }, z.core.$loose>;
        user: z.ZodObject<{
            type: z.ZodDefault<z.ZodString>;
        }, z.core.$loose>;
        code: z.ZodObject<{
            type: z.ZodDefault<z.ZodString>;
        }, z.core.$loose>;
    }, z.core.$strip>;
    endpoints: z.ZodObject<{
        login: z.ZodObject<{
            url: z.ZodOptional<z.ZodString>;
        }, z.core.$strip>;
        client: z.ZodOptional<z.ZodObject<{
            url: z.ZodOptional<z.ZodString>;
        }, z.core.$strip>>;
        authCallback: z.ZodOptional<z.ZodObject<{
            url: z.ZodOptional<z.ZodString>;
        }, z.core.$strip>>;
    }, z.core.$strip>;
    cors: z.ZodObject<{
        allowedOrigins: z.ZodDefault<z.ZodArray<z.ZodString>>;
    }, z.core.$strip>;
}, z.core.$strip>;
/**
 * Full application config schema including all optional module sections.
 * Kept as a plain ZodObject (via .extend) for backward compatibility:
 * - consumers can access .shape (e.g. AppConfigSchema.shape.oauth.shape.jwt)
 * - ts.hocon/zod coercion traverses ZodObject shape, not ZodIntersection
 */
export declare const AppConfigSchema: z.ZodObject<{
    http: z.ZodObject<{
        port: z.ZodDefault<z.ZodCoercedNumber<unknown>>;
        trustProxy: z.ZodDefault<z.ZodBoolean>;
    }, z.core.$strip>;
    oauth: z.ZodObject<{
        jwt: z.ZodPipe<z.ZodTransform<unknown, unknown>, z.ZodObject<{
            issuer: z.ZodOptional<z.ZodString>;
            signingKey: z.ZodDefault<z.ZodObject<{
                provider: z.ZodDefault<z.ZodString>;
                local: z.ZodOptional<z.ZodObject<{
                    algorithm: z.ZodDefault<z.ZodEnum<{
                        HS256: "HS256";
                        RS256: "RS256";
                        ES256: "ES256";
                        EdDSA: "EdDSA";
                    }>>;
                    kid: z.ZodDefault<z.ZodString>;
                    secret: z.ZodOptional<z.ZodString>;
                    privateKey: z.ZodOptional<z.ZodString>;
                    privateKeyPath: z.ZodOptional<z.ZodString>;
                    publicKey: z.ZodOptional<z.ZodString>;
                    publicKeyPath: z.ZodOptional<z.ZodString>;
                    previousKeys: z.ZodDefault<z.ZodArray<z.ZodObject<{
                        kid: z.ZodString;
                        publicKey: z.ZodOptional<z.ZodString>;
                        publicKeyPath: z.ZodOptional<z.ZodString>;
                        expiresAt: z.ZodString;
                    }, z.core.$strip>>>;
                }, z.core.$loose>>;
            }, z.core.$loose>>;
        }, z.core.$strip>>;
        accessToken: z.ZodObject<{
            expiresIn: z.ZodDefault<z.ZodCoercedNumber<unknown>>;
        }, z.core.$strip>;
        refreshToken: z.ZodObject<{
            expiresIn: z.ZodDefault<z.ZodCoercedNumber<unknown>>;
        }, z.core.$strip>;
        grants: z.ZodObject<{}, z.core.$loose>;
    }, z.core.$strip>;
    session: z.ZodObject<{
        secret: z.ZodString;
        maxAge: z.ZodDefault<z.ZodCoercedNumber<unknown>>;
        secure: z.ZodDefault<z.ZodBoolean>;
        sameSite: z.ZodDefault<z.ZodEnum<{
            lax: "lax";
            none: "none";
            strict: "strict";
        }>>;
        domain: z.ZodDefault<z.ZodNullable<z.ZodString>>;
        storage: z.ZodObject<{
            type: z.ZodDefault<z.ZodString>;
            redis: z.ZodOptional<z.ZodObject<{
                url: z.ZodDefault<z.ZodString>;
                password: z.ZodOptional<z.ZodString>;
            }, z.core.$strip>>;
        }, z.core.$loose>;
    }, z.core.$strip>;
    rateLimit: z.ZodObject<{
        login: z.ZodObject<{
            windowMs: z.ZodCoercedNumber<unknown>;
            limit: z.ZodCoercedNumber<unknown>;
        }, z.core.$strip>;
    }, z.core.$strip>;
    federations: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodObject<{
        enabled: z.ZodPipe<z.ZodTransform<unknown, unknown>, z.ZodDefault<z.ZodBoolean>>;
        type: z.ZodOptional<z.ZodString>;
    }, z.core.$loose>>>;
    repositories: z.ZodObject<{
        client: z.ZodObject<{
            type: z.ZodDefault<z.ZodString>;
        }, z.core.$loose>;
        user: z.ZodObject<{
            type: z.ZodDefault<z.ZodString>;
        }, z.core.$loose>;
        code: z.ZodObject<{
            type: z.ZodDefault<z.ZodString>;
        }, z.core.$loose>;
    }, z.core.$strip>;
    endpoints: z.ZodObject<{
        login: z.ZodObject<{
            url: z.ZodOptional<z.ZodString>;
        }, z.core.$strip>;
        client: z.ZodOptional<z.ZodObject<{
            url: z.ZodOptional<z.ZodString>;
        }, z.core.$strip>>;
        authCallback: z.ZodOptional<z.ZodObject<{
            url: z.ZodOptional<z.ZodString>;
        }, z.core.$strip>>;
    }, z.core.$strip>;
    cors: z.ZodObject<{
        allowedOrigins: z.ZodDefault<z.ZodArray<z.ZodString>>;
    }, z.core.$strip>;
}, z.core.$strip>;
export type AppConfig = z.infer<typeof AppConfigSchema>;
//# sourceMappingURL=application.schema.d.mts.map