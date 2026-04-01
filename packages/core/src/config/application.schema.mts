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

// HOCON values can be boolean literals (true) or env var strings ("false").
// hoconBoolean only accepts strings; z.boolean() only accepts booleans.
// Union handles both cases.
const hoconBoolean = z.union([z.boolean(), z.stringbool()]);

const rateLimitSchema = z.object({
	windowMs: z.coerce.number(),
	limit: z.coerce.number(),
});

export const AppConfigSchema = z.object({
	http: z.object({
		port: z.coerce.number().default(3000),
		trustProxy: hoconBoolean.default(false),
	}),
	oauth: z.object({
		jwt: z.object({
			secret: z.string(),
			issuer: z.string().optional(),
		}),
		accessToken: z.object({
			expiresIn: z.coerce.number().default(3600),
		}),
		refreshToken: z.object({
			expiresIn: z.coerce.number().default(86400),
		}),
		grants: z.object({
			session: z.object({ enabled: hoconBoolean.default(true) }),
			authorization: z.object({ enabled: hoconBoolean.default(true) }),
			refresh_token: z.object({ enabled: hoconBoolean.default(true) }),
			did: z.object({
				enabled: hoconBoolean.default(true),
				messageMaxAgeSec: z.coerce.number().default(300),
			}),
		}),
	}),
	session: z.object({
		secret: z.string(),
		maxAge: z.coerce.number().default(3600000),
		secure: hoconBoolean.default(true),
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
			enabled: hoconBoolean.default(false),
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
			type: z.string().default("http"),
			baseURL: z.string().optional(),
			timeout: z.coerce.number().default(5000),
		}),
		code: z.object({
			type: z.string().default("redis"),
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
