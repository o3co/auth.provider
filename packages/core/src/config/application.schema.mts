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

export const AppConfigSchema = z.object({
	http: z.object({
		port: z.coerce.number().default(3000),
		trustProxy: z.boolean().default(false),
	}),
	oauth: z.object({
		jwt: z.object({
			algorithm: z.enum(["HS256", "RS256", "ES256", "EdDSA"]).default("HS256"),
			secret: z.string().optional(),
			issuer: z.string().optional(),
			kid: z.string().default("v0"),
			privateKey: z.string().optional(),
			privateKeyPath: z.string().optional(),
			publicKey: z.string().optional(),
			publicKeyPath: z.string().optional(),
			previousKeys: z.array(z.object({
				kid: z.string(),
				publicKey: z.string().optional(),
				publicKeyPath: z.string().optional(),
				expiresAt: z.string(),
			})).default([]),
		}).superRefine((data, ctx) => {
			if (data.algorithm === "HS256" && !data.secret) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: "secret is required for HS256 algorithm",
					path: ["secret"],
				});
			}
			const isAsymmetric = data.algorithm === "RS256" || data.algorithm === "ES256" || data.algorithm === "EdDSA";
			if (isAsymmetric) {
				if (!data.privateKey && !data.privateKeyPath) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: "privateKey or privateKeyPath is required for asymmetric algorithms",
						path: ["privateKey"],
					});
				}
				if (!data.publicKey && !data.publicKeyPath) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: "publicKey or publicKeyPath is required for asymmetric algorithms",
						path: ["publicKey"],
					});
				}
			}
			for (const [i, key] of data.previousKeys.entries()) {
				if (!key.publicKey && !key.publicKeyPath) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: "publicKey or publicKeyPath is required for each previousKeys entry",
						path: ["previousKeys", i, "publicKey"],
					});
				}
			}
		}),
		accessToken: z.object({
			expiresIn: z.coerce.number().default(3600),
		}),
		refreshToken: z.object({
			expiresIn: z.coerce.number().default(86400),
		}),
		grants: z.object({
			session: z.object({ enabled: z.boolean().default(true) }),
			authorization: z.object({ enabled: z.boolean().default(true) }),
			refresh_token: z.object({ enabled: z.boolean().default(true) }),
		}).passthrough(),
	}),
	session: z.object({
		secret: z.string(),
		maxAge: z.coerce.number().default(3600000),
		secure: z.boolean().default(true),
		sameSite: z.enum(["lax", "none", "strict"]).default("lax"),
		domain: z.string().nullable().default(null),
		storage: z.object({
			type: z.string().default("redis"),
			redis: z.object({
				url: z.string().default("redis://localhost:6379"),
				password: z.string().optional(),
			}),
		}),
	}),
	rateLimit: z.object({
		login: rateLimitSchema,
		token: rateLimitSchema,
		authorize: rateLimitSchema,
	}),
	federations: z.object({
		google: z.object({
			enabled: z.boolean().default(false),
			clientId: z.string().optional(),
			clientSecret: z.string().optional(),
			callbackURL: z.string().optional(),
		}),
	}),
	clients: z.object({
		client: z.object({
			type: z.string().default("yaml"),
			path: z.string().default("./config/clients.yaml"),
		}),
		user: z.object({
			type: z.string().default("yaml"),
			authenticateUrl: z.string().optional(),
			authenticateByTokenUrl: z.string().optional(),
			path: z.string().default("./config/users.yaml"),
			timeout: z.coerce.number().default(5000),
		}),
		code: z.object({
			type: z.string().default("memory"),
			endpointUri: z.string().optional(),
			password: z.string().optional(),
			defaultExpiresIn: z.coerce.number().default(600),
		}),
	}),
	endpoints: z.object({
		login: z.object({ url: z.string().optional() }),
		client: z.object({ url: z.string().optional() }),
		authCallback: z.object({ url: z.string().optional() }),
	}),
	cors: z.object({
		allowedOrigins: z.array(z.string()).default([]),
	}),
});

export type AppConfig = z.infer<typeof AppConfigSchema>;
