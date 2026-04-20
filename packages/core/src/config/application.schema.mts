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
import { z } from "zod";

const rateLimitSchema = z.object({
	windowMs: z.coerce.number(),
	limit: z.coerce.number(),
});

const signingKeyLocalSchema = z
	.object({
		algorithm: z.enum(["HS256", "RS256", "ES256", "EdDSA"]).default("HS256"),
		kid: z.string().default("v0"),
		secret: z.string().optional(),
		privateKey: z.string().optional(),
		privateKeyPath: z.string().optional(),
		publicKey: z.string().optional(),
		publicKeyPath: z.string().optional(),
		previousKeys: z
			.array(
				z.object({
					kid: z.string(),
					publicKey: z.string().optional(),
					publicKeyPath: z.string().optional(),
					expiresAt: z.string(),
				}),
			)
			.default([]),
	})
	.passthrough();

const signingKeySchema = z
	.object({
		provider: z.string().default("local"),
		local: signingKeyLocalSchema.optional(),
	})
	.passthrough();

const LEGACY_JWT_FIELDS = [
	"algorithm",
	"kid",
	"secret",
	"privateKey",
	"privateKeyPath",
	"publicKey",
	"publicKeyPath",
	"previousKeys",
] as const;

const jwtSchemaBase = z.object({
	issuer: z.string().optional(),
	signingKey: signingKeySchema.default({ provider: "local" }),
});

/**
 * jwtSchema wraps the base object schema with a preprocess step that detects
 * legacy flat oauth.jwt.* fields before zod strips unknown keys.
 *
 * Zod's default object behavior strips unknown keys before superRefine sees
 * the data, so superRefine on the parsed output cannot detect stripped fields.
 * z.preprocess runs on the raw input and can emit a ZodError early.
 */
const jwtSchema = z.preprocess((raw, ctx) => {
	if (typeof raw === "object" && raw !== null && !Array.isArray(raw)) {
		const rawObj = raw as Record<string, unknown>;
		const legacyPresent = LEGACY_JWT_FIELDS.filter((field) => field in rawObj);
		if (legacyPresent.length > 0) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message:
					`oauth.jwt has legacy flat fields (${legacyPresent.join(", ")}). ` +
					`Migrate to nested shape: oauth.jwt.signingKey.local.<field>. ` +
					`See packages/core/README.md for migration guide.`,
				path: [legacyPresent[0]],
			});
		}
	}
	return raw;
}, jwtSchemaBase);

/**
 * Minimal always-required config for the auth provider core.
 * DID-only deployments only need these sections.
 */
export const CoreConfigSchema = z.object({
	http: z.object({
		port: z.coerce.number().default(3000),
		trustProxy: z.boolean().default(false),
	}),
	oauth: z.object({
		jwt: jwtSchema,
		accessToken: z.object({
			expiresIn: z.coerce.number().default(3600),
		}),
		refreshToken: z.object({
			expiresIn: z.coerce.number().default(86400),
		}),
		grants: z.object({}).passthrough(),
	}),
});

export type CoreConfig = z.infer<typeof CoreConfigSchema>;

/**
 * Composes a config schema by merging module-specific schemas with the CoreConfigSchema.
 * Each module can declare its required config shape; the resulting schema validates
 * the intersection of core + all module schemas.
 */
export function composeConfigSchema(moduleSchemas: z.ZodObject<z.ZodRawShape>[]): z.ZodType {
	let schema: z.ZodType = CoreConfigSchema;
	for (const moduleSchema of moduleSchemas) {
		schema = schema.and(moduleSchema);
	}
	return schema;
}

export const fullSectionsSchema = z.object({
	session: z.object({
		secret: z.string(),
		maxAge: z.coerce.number().default(3600000),
		secure: z.boolean().default(true),
		sameSite: z.enum(["lax", "none", "strict"]).default("lax"),
		domain: z.string().nullable().default(null),
		storage: z
			.object({
				type: z.string().default("redis"),
				redis: z
					.object({
						url: z.string().default("redis://localhost:6379"),
						password: z.string().optional(),
					})
					.optional(),
			})
			.passthrough(),
	}),
	rateLimit: z.object({
		login: rateLimitSchema,
		token: rateLimitSchema,
		authorize: rateLimitSchema,
	}),
	federations: z
		.record(
			z.string(),
			z
				.object({
					// z.coerce.boolean() so that env-var strings like "true"/"false" are accepted.
					// Note: any truthy value (e.g. the string "false") coerces to true — same
					// behavior as rateLimitSchema which uses z.coerce.number() for parity.
					enabled: z.coerce.boolean().default(false),
					type: z.string().optional(),
				})
				.passthrough(),
		)
		.default({}),
	clients: z.object({
		client: z
			.object({
				type: z.string().default("yaml"),
			})
			.passthrough(),
		user: z
			.object({
				type: z.string().default("yaml"),
			})
			.passthrough(),
		code: z
			.object({
				type: z.string().default("memory"),
			})
			.passthrough(),
	}),
	endpoints: z.object({
		login: z.object({ url: z.string().optional() }),
		client: z.object({ url: z.string().optional() }).optional(),
		authCallback: z.object({ url: z.string().optional() }).optional(),
	}),
	cors: z.object({
		allowedOrigins: z.array(z.string()).default([]),
	}),
});

/**
 * Full application config schema including all optional module sections.
 * Kept as a plain ZodObject (via .extend) for backward compatibility:
 * - consumers can access .shape (e.g. AppConfigSchema.shape.oauth.shape.jwt)
 * - ts.hocon/zod coercion traverses ZodObject shape, not ZodIntersection
 */
export const AppConfigSchema = CoreConfigSchema.extend(fullSectionsSchema.shape);

export type AppConfig = z.infer<typeof AppConfigSchema>;
