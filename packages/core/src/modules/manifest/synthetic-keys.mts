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

import type { RateLimitSpec } from "../../ratelimit/types.mjs";
import type { SessionRequirementResolver } from "../../session-admission/requirement.mjs";
import type { SessionCloseNotifier } from "../../session-lifecycle/notifier.mjs";
import type {
	ExchangeTokenValidator,
	FederationProvider,
	GrantHandler,
	MfaFactor,
} from "./contributes-map.mjs";

/**
 * Read-only projection of the boot planner's `grants` collector, for route
 * factories that dispatch by `grant_type` at request time. The planner builds
 * it before the `provides` factories run and freezes the registry behind it.
 * A grant whose factory answered `null` (switched off) is absent from both
 * `get` and `entries`, exactly like a grant type no module contributes.
 */
export interface GrantHandlerResolver {
	readonly get: (grantType: string) => GrantHandler | undefined;
	readonly entries: () => IterableIterator<readonly [string, GrantHandler]>;
}

/** Read-only projection of the boot planner's `tokenExchangeValidators` collector. */
export interface TokenExchangeValidatorResolver {
	readonly get: (tokenType: string) => ExchangeTokenValidator | undefined;
	readonly entries: () => IterableIterator<readonly [string, ExchangeTokenValidator]>;
}

/**
 * Read-only projection of the boot planner's `mfaFactors` collector: every
 * contributed second factor by kind (ADR 2026-09-25-multi-factor-authentication).
 * A kind whose factory answered `null` (switched off by its configuration) is
 * absent from both `get` and `entries`.
 */
export interface MfaFactorResolver {
	readonly get: (kind: string) => MfaFactor | undefined;
	readonly entries: () => IterableIterator<readonly [string, MfaFactor]>;
}

/**
 * Read-only projection of the boot planner's `rateLimitBudgets` collector:
 * every contributed budget by the prefix it limits. A prefix whose factory
 * answered `null` (switched off by its module's settings) is absent from both
 * `get` and `entries`. A limiter reads it at request time and weighs it
 * against what an operator configured on the limiter for that prefix.
 */
export interface RateLimitBudgetResolver {
	readonly get: (prefix: string) => RateLimitSpec | undefined;
	readonly entries: () => IterableIterator<readonly [string, RateLimitSpec]>;
}

/**
 * Read-only projection of the boot planner's `sessionCloseNotifiers`
 * collector: the one contributed notifier, or `undefined` when none is. Read
 * when a close runs; a read while the `provides` factories run throws.
 */
export interface SessionCloseNotifierResolver {
	readonly get: () => SessionCloseNotifier | undefined;
}

/** Re-export for consumers that name the `federationProviders` slot's value type. */
export type { FederationProvider };

/**
 * ComponentMap keys whose values the boot planner builds itself. Boot rejects
 * any of them in a module's `provides`, in `bootstrapComponents` and in
 * `overrideComponents` (`synthetic-key-collision`). Each `…Resolver` projects
 * the contribution kind of the same stem; `federationRedirectPolicies` is
 * typed in `@o3co/auth-provider-session`. `deploymentMode` is the
 * configuration's `core.deployment.mode` (`deployment/mode.mts`), typed with its
 * slot in `deployment/types.mts`; `tokenBindingSettings` is its
 * `core.tokenBinding` (`resolveTokenBindingSettings`), typed with its slot in
 * `middleware/tokenBinding.mts`; `federationSettings` is its
 * `core.federations` (`boot/federation-settings.mts`), typed with its slot in
 * `federations/settings.mts`; `outboundPolicy` is its `core.outbound`
 * (`outboundPolicyOf`, `net/outbound-fetch.mts`), typed with its slot in
 * `net/outbound-policy.mts`.
 *
 * Immutability rests on the `ReadonlySet<string>` type. `Object.freeze` does
 * not stop the built-in Set methods from mutating `[[SetData]]`, so a cast to
 * `Set<string>` bypasses the contract.
 */
export const SYNTHETIC_COMPONENT_KEYS: ReadonlySet<string> = Object.freeze(
	new Set([
		"federationProviders",
		"tokenExchangeValidatorResolver",
		"grantHandlerResolver",
		"federationRedirectPolicyResolver",
		"mfaFactorResolver",
		"sessionRequirementResolver",
		"rateLimitBudgetResolver",
		"sessionCloseNotifierResolver",
		// Boot-planner-owned (createApp pre-seeds it). A consumer-supplied
		// registrar would diverge silently: the planner drains its own while
		// builders register cleanups on the consumer's.
		"lifecycleRegistrar",
		// Same for readiness: the planner would read its own empty registrar
		// while builders register probes on the consumer's, and `/readyz` would
		// answer ready with nothing probed.
		"readinessRegistrar",
		// Filled from the configuration before any provider runs: a module or
		// host that set it would be a second statement of the replica count,
		// beside the one the replica-safety guard reads.
		"deploymentMode",
		// Filled the same way, from `core.tokenBinding`: a module or host that
		// set it would be a second source of the token-binding settings, beside
		// the one boot's dispatch policy reads.
		"tokenBindingSettings",
		// Filled the same way, from `core.federations`: a module or host that
		// set it would be a second statement of the federations, beside the
		// one boot dispatches by.
		"federationSettings",
		// Filled the same way, from `core.outbound`: a module or host that set
		// it would be a second statement of the outbound policy, beside the one
		// a fetch built from the configuration reads.
		"outboundPolicy",
	]),
);

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge for the synthetic resolver slots, so a module
// can declare `requires: ["grantHandlerResolver"]` etc. through the typed
// `defineModule` surface.
//
// The planner injects these projections before stage 3 runs the `provides`
// factories (`prepareSyntheticProjections` in `boot/apply-contributions.mts`).
// A provider may hold one but must read it lazily, at request time: the
// contributions behind it register in stage 4, and a read while the provides
// factories run throws and refuses the boot.
//
// Unnamespaced slot names are reserved for o3co; consumers MUST namespace
// their own keys.
//
// TRADE-OFF (NORMATIVE): once merged, the type system no longer rejects a
// module or host that writes one of these slots (`provides`,
// `bootstrapComponents`, `overrideComponents`). `validate-manifests.mts`
// rejects that at runtime (`synthetic-key-collision`); that check is
// authoritative and also covers untyped and dynamically loaded modules. Typed
// `requires`, the read path, is worth more to module authors.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly grantHandlerResolver?: GrantHandlerResolver;
		readonly tokenExchangeValidatorResolver?: TokenExchangeValidatorResolver;
		readonly federationProviders?: ReadonlyMap<string, FederationProvider>;
		readonly mfaFactorResolver?: MfaFactorResolver;
		/** The registered session requirements in registration order, branded by the planner (ADR 2026-09-28-session-admission). */
		readonly sessionRequirementResolver?: SessionRequirementResolver;
		/** Every module's rate-limit budget by prefix, read by a limiter at request time. */
		readonly rateLimitBudgetResolver?: RateLimitBudgetResolver;
		/** The contributed session-close notifier, read by the session lifecycle when a close runs. */
		readonly sessionCloseNotifierResolver?: SessionCloseNotifierResolver;
	}
}
