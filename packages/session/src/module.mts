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

import {
	type AppConfig,
	fullSectionsSchema,
	type Module,
	type ModuleContext,
	type UserRepository,
} from "@o3co/auth-provider-core";
import type { RequestHandler, Router } from "express";
import {
	createFederationProviderFactory,
	type FederationProviderFactory,
} from "./federations/factory.mjs";
import type { FederationProvider } from "./federations/types.mjs";
import * as federationRoutes from "./routes/Federation.mjs";
import * as sessionRoutes from "./routes/Session.mjs";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

const sessionConfigSchema = fullSectionsSchema.pick({
	session: true,
	rateLimit: true,
	federations: true,
	endpoints: true,
	cors: true,
});

export type SessionModuleOptions = {
	userRepository: UserRepository;
	express?: ExpressLike;
	/** Session TTL in milliseconds for new federation-created UserSessions. Default 24h. */
	sessionTtlMs?: number;
	/** Federation provider factory configured by the composition root. Defaults to an empty factory. */
	federationProviderFactory?: FederationProviderFactory;
};

type SessionModuleInternalOptions = SessionModuleOptions & {
	/** For testing only — replace sessionRoutes.createRouter to capture call arguments. */
	_createSessionRouter?: typeof sessionRoutes.createRouter;
	/** For testing only — replace federationRoutes.createRouter to capture call arguments. */
	_createFederationRouter?: typeof federationRoutes.createRouter;
};

/**
 * Internal implementation — accepts an optional factory override for testing.
 * Not part of the public API; tests import this directly via the `#/` alias.
 */
export const _sessionModuleImpl = (params: SessionModuleInternalOptions): Module => ({
	name: "session",
	configSchema: sessionConfigSchema,
	async init(context: ModuleContext): Promise<void> {
		const express: ExpressLike =
			params.express ??
			(await (async () => {
				const mod = await import(context.pathResolver("express"));
				return mod.default as ExpressLike;
			})());
		const config = context.config as AppConfig;

		// Validate that required stores are present before proceeding.
		if (!context.userSessionStore || !context.federationTokenStore) {
			throw new Error(
				"session module requires userSessionStore and federationTokenStore in ModuleContext",
			);
		}

		// Build federation provider factory (or use injected stub in tests).
		const factory: FederationProviderFactory =
			params.federationProviderFactory ?? createFederationProviderFactory();

		// Normalize federation config entries and build the provider Map.
		const federationProviders = new Map<string, FederationProvider>();

		// Build the providerCallbackUrls map from config.federations.
		const providerCallbackUrls = new Map<string, string>();

		for (const [name, section] of Object.entries(config.federations)) {
			if (!section.enabled) continue;

			const type = (typeof section.type === "string" ? section.type : undefined) ?? name;
			const subSection = (section as Record<string, unknown>)[type];
			const isNested =
				typeof subSection === "object" && subSection !== null && !Array.isArray(subSection);

			// Reject mixed shape: both top-level credential fields and a nested sub-section present.
			if (isNested) {
				const flatFieldsPresent = ["clientId", "clientSecret", "callbackURL"].filter(
					(k) => k in (section as Record<string, unknown>),
				);
				if (flatFieldsPresent.length > 0) {
					throw new Error(
						`federations.${name}: mixed shape — remove top-level ${flatFieldsPresent.join("/")} OR the ${type} { ... } sub-section`,
					);
				}
			}

			const rawBuilderConfig = isNested
				? (() => {
						// Nested: start from top-level passthrough fields, then overlay the sub-section.
						// Exclude control fields (enabled/type) AND the nested sub-section key itself
						// so they don't appear twice or shadow sub-section fields.
						const {
							enabled: _e,
							type: _t,
							[type]: _sub,
							...topLevel
						} = section as Record<string, unknown>;
						return { type, ...topLevel, ...(subSection as Record<string, unknown>) };
					})()
				: { type, ...(section as Record<string, unknown>) };

			// Strip control fields that must not be forwarded to the builder.
			// For nested shape, enabled/type were already stripped inside the IIFE above;
			// for flat shape we strip them here. Using distinct names avoids shadowing.
			const {
				enabled: _enabled,
				type: _type,
				...flatConfig
			} = rawBuilderConfig as Record<string, unknown>;

			// Inject context fields from AppConfig that provider builders need for redirect validation.
			const sessionDomain =
				// config.session.domain: string | null — pass through when non-null
				typeof config.session.domain === "string" ? config.session.domain : undefined;
			const authCallbackUrl =
				// config.endpoints.authCallback: optional section — used to build post-login redirect
				config.endpoints.authCallback?.url ?? undefined;
			const clientUrl =
				// config.endpoints.client: optional section — fallback URL when no redirectTo in session
				config.endpoints.client?.url ?? undefined;

			const provider = await factory.create({
				type,
				name,
				...flatConfig,
				sessionDomain,
				authCallbackUrl,
				clientUrl,
			});

			// Invariant guard: the provider's name must equal the config key so that
			// routes/Federation.mts can look up the provider by the :name route param.
			// Custom builders must propagate config.name to FederationProvider.name.
			if (provider.name !== name) {
				throw new Error(
					`federations.${name}: provider builder returned name="${provider.name}", expected "${name}". ` +
						`Custom builders must propagate config.name to FederationProvider.name to preserve the config-key ↔ route-param invariant.`,
				);
			}

			federationProviders.set(name, provider);

			// Extract callbackURL for this provider's providerCallbackUrls entry.
			// The callbackURL lives in flatConfig (already extracted from nested/flat shape).
			const callbackURL =
				typeof flatConfig.callbackURL === "string" ? flatConfig.callbackURL : undefined;
			if (!callbackURL) {
				throw new Error(`federations.${name}: callbackURL is required when federation is enabled`);
			}
			providerCallbackUrls.set(name, callbackURL);
		}

		// Expose a snapshot of the federation providers for other modules that need
		// to resolve providers at request time (e.g. oauth's /oauth/logout). A copy
		// is passed — not the original Map — so consumers cannot corrupt the session
		// module's internal provider registry by mutating the shared reference.
		context.federationProviders = new Map(federationProviders);

		// Mount session routes
		const _csr = params._createSessionRouter ?? sessionRoutes.createRouter;
		context.router.use(
			"/session",
			_csr(express, {
				userRepository: params.userRepository,
				config,
				userSessionStore: context.userSessionStore,
				sessionTtlMs: params.sessionTtlMs,
			}),
		);

		// Mount federation routes
		const _cfr = params._createFederationRouter ?? federationRoutes.createRouter;
		context.router.use(
			"/session",
			_cfr(express, {
				config,
				federationProviders,
				providerCallbackUrls,
				userRepository: params.userRepository,
				userSessionStore: context.userSessionStore,
				federationTokenStore: context.federationTokenStore,
				sessionTtlMs: params.sessionTtlMs,
			}),
		);
	},
});

/**
 * Top-level session module factory.
 *
 * Public API — does not expose test-only options. Tests should use `_sessionModuleImpl` directly.
 */
export const sessionModule = (opts: SessionModuleOptions): Module => _sessionModuleImpl(opts);
