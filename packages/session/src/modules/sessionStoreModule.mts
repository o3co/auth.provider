/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import {
	BootError,
	type BuilderContext,
	checkDeploymentMode,
	coerceBooleanFromEnv,
	consoleLogger,
	defineModule,
	describeWeakSecret,
	MAX_DURATION_MS,
	MIN_SECRET_ENTROPY_BYTES,
	measureSecretEntropyBytes,
	type ReplicaSafetyDeclaration,
	type SessionCookiePolicy,
	wholeNumberInRangeFromEnv,
} from "@o3co/auth-provider-core";
import session from "express-session";
import { z } from "zod";
import { createSessionCsrfTokenSigner } from "../csrf-token-signer.mjs";
import { guardCookieSession } from "../internal/cookieSession.mjs";
import {
	type SessionCookieConfigSlice,
	sessionCookiePolicyFrom,
	sessionCookieRefusal,
} from "../session-cookie-policy.mjs";
import { createSessionStoreFactory, registerBuiltinSessionStores } from "../store/factory.mjs";

/** The secret's key and variable, as refusals name them. */
const SECRET = { configKey: "session-store.secret", envVar: "SESSION_STORE_SECRET" } as const;

/**
 * The schema of `session-store {}`, the module's own section: the session
 * cookie (its name, lifetime and attributes, and the secret that signs it)
 * and the store express-session keeps sessions in. Strict at every level:
 * the storage types are the store factory's built-in ones, which the route
 * registers itself, so `storage` declares the one block a type takes options
 * from (`redis`) and refuses any other. A section that yields no session
 * cookie is refused naming the key (`sessionCookieRefusal`), and a secret
 * below the 256-bit floor naming the secret. The secret has no default:
 * absent, the module refuses to build (`requireSecret`).
 */
export const sessionStoreConfigSchema = z
	.object({
		// Signs the cookie that is the authenticated session, so guessing it
		// forges logins: held to the floor the JWT signing secret is held to.
		secret: z
			.string()
			.superRefine((value, ctx) => {
				const actualBytes = measureSecretEntropyBytes(value);
				if (actualBytes < MIN_SECRET_ENTROPY_BYTES) {
					ctx.addIssue({ code: "custom", message: describeWeakSecret(actualBytes, SECRET) });
				}
			})
			.optional(),
		name: z.string(),
		// Positive and bounded: 0 makes express-session emit an
		// already-expired cookie.
		maxAge: wholeNumberInRangeFromEnv(1, MAX_DURATION_MS),
		secure: coerceBooleanFromEnv,
		sameSite: z.enum(["lax", "none", "strict"]),
		domain: z.string().nullable(),
		storage: z
			.object({
				type: z.string(),
				// Per-type options for `storage.type = "redis"`: the route spreads
				// `storage[storage.type]` into the store factory.
				redis: z.object({ url: z.string(), password: z.string().optional() }).strict().optional(),
			})
			.strict(),
	})
	.strict()
	.superRefine((section, ctx) => {
		const refusal = sessionCookieRefusal(section);
		if (refusal !== undefined) {
			ctx.addIssue({ code: "custom", path: [refusal.key], message: refusal.message });
		}
	});

/** `session-store {}` as its schema leaves it. */
type SessionStoreSection = z.output<typeof sessionStoreConfigSchema>;

/**
 * The secret the session cookie is signed with; a refusal naming the key and
 * its variable when the section carries none.
 */
function requireSecret(section: SessionStoreSection): string {
	if (section.secret !== undefined) return section.secret;
	throw new Error(
		`${SECRET.configKey} is not set: it signs the session cookie, and has no default. Set ${SECRET.envVar} to at least 32 bytes of random material (openssl rand -hex 32).`,
	);
}

/**
 * The module's section, with the paths it moved from and the variables
 * renamed with them: each key of the session cookie and its store moved from
 * `session` to `session-store`, and its `SESSION_*` variable to
 * `SESSION_STORE_*`.
 */
const SECTION = {
	schema: sessionStoreConfigSchema,
	reference: new URL("../../config/reference.conf", import.meta.url),
	relocatedFrom: {
		"session.secret": "secret",
		"session.name": "name",
		"session.maxAge": "maxAge",
		"session.secure": "secure",
		"session.sameSite": "sameSite",
		"session.domain": "domain",
		"session.storage": { to: "storage", environmentVariable: null },
		"session.storage.type": "storage.type",
		"session.storage.redis.url": "storage.redis.url",
		"session.storage.redis.password": "storage.redis.password",
	},
	renamedVariables: {
		SESSION_SECRET: "session.secret",
		SESSION_NAME: "session.name",
		SESSION_MAX_AGE: "session.maxAge",
		SESSION_SECURE: "session.secure",
		SESSION_SAME_SITE: "session.sameSite",
		SESSION_DOMAIN: "session.domain",
		SESSION_STORAGE_TYPE: "session.storage.type",
		SESSION_STORAGE_REDIS_URL: "session.storage.redis.url",
		SESSION_STORAGE_REDIS_PASSWORD: "session.storage.redis.password",
	},
} as const;

const MODULE_NAME = "session-store";

/**
 * What forks per replica when `session-store.storage.type = "memory"`. Quoted
 * by the replica-safety guard into a refused boot and into the unset-mode
 * warning, so it names the consequence rather than the fix.
 */
const MEMORY_STORE_REPLICA_SAFETY: ReplicaSafetyDeclaration = {
	unsafe: true,
	reason:
		"the express-session store forks per replica — a login served by one replica is unknown to the others, so a browser whose next request lands elsewhere is logged out, logout clears only the session the replica it lands on can see, and every session is lost on restart",
};

/** The slice of config this module's manifest is built from. */
export interface SessionStoreModuleConfig {
	readonly "session-store"?: { readonly storage?: { readonly type?: unknown } };
}

const storageTypeOf = (config: SessionStoreModuleConfig | undefined): unknown =>
	config?.["session-store"]?.storage?.type;

/**
 * The module's replica safety, from its parsed section: express-session's
 * per-process `MemoryStore` for `storage.type = "memory"`; nothing for every
 * other type, each a shared store.
 */
const replicaSafetyOf = (section: SessionStoreSection): ReplicaSafetyDeclaration | undefined =>
	section.storage.type === "memory" ? MEMORY_STORE_REPLICA_SAFETY : undefined;

/** One policy per `session-store` section: the route mounts the cookie the slot holds. */
const policies = new WeakMap<SessionCookieConfigSlice, SessionCookiePolicy>();

function sessionCookieOf(session: SessionCookieConfigSlice): SessionCookiePolicy {
	let policy = policies.get(session);
	if (policy === undefined) {
		policy = sessionCookiePolicyFrom(session);
		policies.set(session, policy);
	}
	return policy;
}

function buildSessionStoreModule(
	replicaSafety:
		| ReplicaSafetyDeclaration
		| ((section: SessionStoreSection) => ReplicaSafetyDeclaration | undefined)
		| undefined,
) {
	// Written type arguments infer nothing, so the section schema (none) and
	// the provided keys `authoritative` is typed against are written too.
	return defineModule<
		"deploymentMode",
		"lifecycleRegistrar" | "readinessRegistrar" | "logger",
		typeof sessionStoreConfigSchema,
		"sessionCookiePolicy" | "csrfTokenSigner"
	>({
		name: MODULE_NAME,
		section: SECTION,
		// `deploymentMode`: memory storage is refused under `multi`, so a mode
		// read as absent must not lift that.
		requires: ["deploymentMode"],
		// `logger` is optional: the redis client's error handler, and the
		// middleware's report of a store that cannot load or save a session,
		// fall back to consoleLogger when the composition wires no logger slot.
		optional: ["lifecycleRegistrar", "readinessRegistrar", "logger"],
		...(replicaSafety === undefined ? {} : { replicaSafety }),
		provides: {
			// The session cookie's attributes, for a module that sets a cookie of
			// its own beside the session's or sizes what must outlive a session:
			// this module owns the cookie, and the others require the slot instead
			// of reading `session-store.*`. They are the attributes express-session
			// is given below; the signing secret is not among them.
			sessionCookiePolicy: (deps) => sessionCookieOf(deps.section),
			// The CSRF token's signature, under a key derived from the secret this
			// module owns: the session module's guard and routes sign through it,
			// and neither the secret nor the key leaves the signer.
			csrfTokenSigner: (deps) => createSessionCsrfTokenSigner(requireSecret(deps.section)),
		},
		// The route mounts the cookie `session-store.*` describes: an override
		// would describe a cookie no browser is given.
		authoritative: ["sessionCookiePolicy"],
		contributes: {
			routes: [
				async (deps) => {
					const section = deps.section;
					const secret = requireSecret(section);
					const replicas = checkDeploymentMode(
						deps.deploymentMode,
						"session-store: deploymentMode",
					);
					const ctx: BuilderContext = {
						lifecycle: deps.lifecycleRegistrar,
						readiness: deps.readinessRegistrar,
						logger: deps.logger,
					};
					const factory = createSessionStoreFactory(ctx);
					registerBuiltinSessionStores(factory);
					const storageSlice = section.storage as { type: string } & Record<string, unknown>;
					// The stage-1 guard refused this combination already when the
					// module declared from the section it was booted with. A module
					// `sessionStoreModuleFor` built from another config told the
					// guard nothing: refuse it here, with the same reason, rather
					// than mount a per-process store.
					if (storageSlice.type === "memory" && replicas === "multi") {
						throw new BootError({
							stage: "applyContributions",
							reason: "replica-unsafe-adapter",
							message: `core.deployment.mode is "multi" but session-store.storage.type is "memory", which cannot be shared across replicas: ${MEMORY_STORE_REPLICA_SAFETY.reason}. Set session-store.storage.type = "redis", or set core.deployment.mode = "single".`,
							details: { reason: "replica-unsafe-adapter", modules: [MODULE_NAME] },
						});
					}
					// The slot's cookie, refused before the store opens a connection.
					const cookie = sessionCookieOf(section);
					const store = await factory.create({
						type: storageSlice.type,
						...((storageSlice[storageSlice.type] ?? {}) as Record<string, unknown>),
					});
					// A store error express-session would hand to `next(err)` is
					// answered by the guard: `503` when the session cannot be loaded,
					// one error line either way (`../internal/cookieSession.mts`).
					const middleware = session({
						name: cookie.name,
						secret,
						resave: false,
						saveUninitialized: false,
						store,
						cookie: {
							path: "/",
							httpOnly: true,
							secure: cookie.secure,
							maxAge: cookie.maxAgeMs,
							sameSite: cookie.sameSite,
							domain: cookie.domain,
						},
					});
					// No `before` clause: see the mount-order contract on
					// `sessionStoreModule` below.
					return {
						id: "session-middleware",
						mountPath: "/",
						handler: guardCookieSession(middleware, deps.logger ?? consoleLogger),
					};
				},
			],
		},
	});
}

/**
 * The session-store module built for one config: {@link sessionStoreModule},
 * with its replica safety declared from `config` rather than from the section
 * boot parses. It declares `replicaSafety` when the configured
 * `session-store.storage.type` is `"memory"`, and nothing for every other
 * type, which is what {@link sessionStoreModule} answers for the same
 * section. List {@link sessionStoreModule} instead: it needs no config at
 * composition time.
 */
export function sessionStoreModuleFor(config: SessionStoreModuleConfig) {
	return buildSessionStoreModule(
		storageTypeOf(config) === "memory" ? MEMORY_STORE_REPLICA_SAFETY : undefined,
	);
}

/**
 * The session-store manifest: the express-session middleware as a
 * route at `mountPath: "/"`, built in the boot planner's DI graph so the
 * store's client receives a `BuilderContext.lifecycle` and can register
 * `client.quit()` for disposal.
 *
 * **Mount-order contract**: the route has no `before` / `after` clause,
 * because naming an absent route id raises a `route-order-target-missing`
 * BootError on partial manifests (e.g. an oauth-only deployment without
 * `sessionModule`). Order comes from declarationIndex tie-breaking: the
 * composition root MUST list this module ahead of every session-consuming
 * module in `buildModules(config)` (README, "Browser session store").
 *
 * **Replica safety**: declared from its parsed section.
 * `session-store.storage.type = "memory"` is express-session's per-process
 * `MemoryStore`, the same shape as every memory store the replica-safety
 * guard refuses, so the module declares `replicaSafety` for it: the guard
 * refuses it by name under `core.deployment.mode = "multi"`, listed with the
 * other offenders, warns when the mode is unset, and says nothing under
 * `"single"`. Every other storage type is a shared store and declares
 * nothing.
 */
export const sessionStoreModule = buildSessionStoreModule(replicaSafetyOf);
