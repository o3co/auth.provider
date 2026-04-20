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
	registerBuiltinFederations,
} from "./federations/factory.mjs";
import type { FederationProviderBase } from "./federations/types.mjs";
import { createPassport } from "./passport.mjs";
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
};

type SessionModuleInternalOptions = SessionModuleOptions & {
	/** For testing only — inject a pre-configured factory to skip registration. */
	_federationFactory?: FederationProviderFactory;
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

		// Build federation provider factory (or use injected stub in tests).
		const factory: FederationProviderFactory =
			params._federationFactory ??
			(() => {
				const f = createFederationProviderFactory();
				registerBuiltinFederations(f);
				return f;
			})();

		// Normalize federation config entries and build the provider Map.
		const federationProviders = new Map<string, FederationProviderBase>();
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
			// Custom builders must propagate config.name to FederationProviderBase.name.
			if (provider.name !== name) {
				throw new Error(
					`federations.${name}: provider builder returned name="${provider.name}", expected "${name}". ` +
						`Custom builders must propagate config.name to FederationProviderBase.name to preserve the config-key ↔ passport-strategy-name invariant.`,
				);
			}

			federationProviders.set(name, provider);
		}

		// Initialize passport with pathResolver
		const passport = await createPassport({
			pathResolver: context.pathResolver,
			userRepository: params.userRepository,
			federationProviders,
		});

		// Mount session routes
		context.router.use(
			"/session",
			sessionRoutes.createRouter(express, {
				passport,
				config,
			}),
		);

		// Mount federation routes
		context.router.use(
			"/session",
			federationRoutes.createRouter(express, {
				passport,
				config,
				federationProviders,
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
