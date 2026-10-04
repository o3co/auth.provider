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

import type { RequestHandler } from "express";
import type { z } from "zod";
import type { AuditSink } from "../../audit/types.mjs";
import type { OidcDiscoveryContribution } from "../../discovery/types.mjs";
import type { FederationProvider as ConcreteFederationProvider } from "../../federations/types.mjs";
import type { GrantHandler as ConcreteGrantHandler } from "../../grants/types.mjs";
import type { MfaFactor as ConcreteMfaFactor } from "../../mfa/factor.mjs";
import type { TokenBindingMechanism } from "../../middleware/tokenBinding.mjs";
import type { GrantPolicyHook } from "../../policy/types.mjs";
import type { RateLimitSpec } from "../../ratelimit/types.mjs";
import type { AdmissionActionDeclaration } from "../../session-admission/actions.mjs";
import type { SessionRequirement as ConcreteSessionRequirement } from "../../session-admission/requirement.mjs";
import type { ExchangeTokenValidator as ConcreteExchangeTokenValidator } from "../../token-exchange/validator.mjs";
import type { Contributed } from "./contributed.mjs";
import type { ProviderDeps } from "./provider.mjs";
import type { RouteContributionEntry } from "./route-contribution.mjs";

// Re-exported so the vocabulary has one home and one path: a module author
// reads `Contributed` from the same place as the factory types that use it.
export type { Contributed };

// The value each contribution kind produces: a concrete contract defined in
// core, so registration and use share one type.

/** Type produced by a `GrantFactory<Deps>` contribution. */
export type GrantHandler = ConcreteGrantHandler;

/** Type produced by a `federationTypes` entry's `factory`: the adapter port itself. */
export type FederationProvider = ConcreteFederationProvider;

/**
 * Type produced by an `ExchangeTokenValidatorFactory<Deps>` contribution: the
 * validator contract itself.
 */
export type ExchangeTokenValidator = ConcreteExchangeTokenValidator;

/**
 * Type produced by an `MfaFactorFactory<Deps>` contribution: the contract a
 * second factor implements.
 */
export type MfaFactor = ConcreteMfaFactor;

/**
 * Type produced by a `SessionRequirementFactory<Deps>` contribution: the
 * requirement contract (ADR 2026-09-28-session-admission).
 */
export type SessionRequirement = ConcreteSessionRequirement;

/**
 * Type produced by an `AuditHookFactory<Deps>` contribution: an `AuditSink`
 * core hands every event the `auditSink` slot records, after the slot's own
 * sink and the hooks registered before it (`createAuditFanOut`). An event
 * recorded while a hook runs, in its async context, reaches the slot's own
 * sink alone (`audit_sink_reentered`); work a hook hands to something made
 * outside that context escapes the guard, so a hook must not emit from
 * `record`. Its `record` must be a function, or boot refuses it.
 */
export type AuditHook = AuditSink;

/**
 * Type produced by a `GrantPolicyHookFactory<Deps>` contribution: a
 * `GrantPolicyHook` (`policy/types.mts`), which owns the unsuffixed name.
 */
export type GrantPolicyHookContribution = GrantPolicyHook;

// Per-kind factory types: each is `(deps: Deps) => Value`.

/**
 * A `grants` entry, keyed by grant type. `null` when the grant is switched off
 * by the module's settings: it is then absent from `grantHandlerResolver` —
 * so from the token endpoint's dispatch and discovery's
 * `grant_types_supported` — as a grant type no module contributes is, yet
 * still claimed, so a second contribution of it is a duplicate. It is no
 * override target: an override of it refuses boot
 * (`override-target-missing`), so nothing switches on what its owner switched
 * off. An override may answer `null`, which switches off the grant it
 * replaces.
 */
export type GrantFactory<Deps> = (deps: Deps) => Contributed<GrantHandler | null>;

/**
 * One configured federation as a type's factories receive it: the operator's
 * name for it (the `:name` of its login route and the name its provider and
 * redirect policy register under), its `callbackURL` — a key every entry
 * carries and core reads, handed on here so no type declares it — and the
 * rest of its entry, parsed by the type's `entrySchema`.
 */
export interface FederationInstance<E> {
	readonly name: string;
	readonly callbackURL: string;
	readonly entry: E;
}

/**
 * What a `federationTypes` declaration's `redirectPolicy` answers: the value
 * registered under the `federationRedirectPolicies` contribution kind. The
 * package that owns the redirect policy declares that kind's type, by
 * augmenting `ContributesMap`; with its declaration in the program this is
 * its policy type, and `unknown` without it.
 *
 * The augmentation is read for its type alone: boot refuses a module's
 * `contributes` or `overrides` of `federationRedirectPolicies` at stage 1
 * (`contribution-kind-guarded`), and registers each policy from the type its
 * `core.federations` entry names. The key stays declared, by its owner, until
 * the redirect-policy contract is core's, since this type is read off it.
 */
export type FederationRedirectPolicyContribution = ContributesMap extends {
	readonly federationRedirectPolicies?: {
		readonly [name: string]: (deps: never) => infer Answer;
	};
}
	? Awaited<Answer>
	: unknown;

/**
 * A `federationTypes` entry: what one federation package handles, keyed by the
 * `type` a `core.federations` entry names (`"oidc"`, `"google"`). It holds
 * the schema an entry of that type is parsed with, and the two factories boot
 * calls for each enabled entry of the type: the provider and its redirect
 * policy, which register under the entry's name as a pair.
 *
 * Author it with `defineFederationType`, which infers `E` from `entrySchema` so
 * a schema and factories that disagree do not compile. Written inline, `E` is
 * `unknown` (the record cannot type each key, and a method is bivariant in
 * its entry), so nothing ties an annotated entry to the schema.
 *
 * Boot reads the schema and both factories once, at stage 1; changing the
 * declaration afterwards changes nothing registered.
 */
export interface FederationTypeContribution<Deps, E = unknown> {
	/**
	 * The schema of an entry of this type: the keys the adapter reads. The keys
	 * core owns on every entry (`enabled`, `type`, `trustUpstreamAmr`,
	 * `callbackURL`) are stripped first, so a strict schema names only the
	 * type's keys.
	 */
	readonly entrySchema: z.ZodType<E>;
	/**
	 * Builds the provider for one configured entry. Its `name` must be the
	 * entry's: the provider registers under it, and the redirect policy is
	 * found by it.
	 */
	factory(deps: Deps, instance: FederationInstance<E>): Contributed<FederationProvider>;
	/** Builds the redirect policy for the same entry, which registers beside its provider. */
	redirectPolicy(
		deps: Deps,
		instance: FederationInstance<E>,
	): Contributed<FederationRedirectPolicyContribution>;
}
export type ExchangeTokenValidatorFactory<Deps> = (
	deps: Deps,
) => Contributed<ExchangeTokenValidator>;
/**
 * An `mfaFactors` entry. `null` when the factor is switched off by config: the
 * kind is then absent from `mfaFactorResolver` yet still claimed, so a second
 * contribution of it is a duplicate.
 */
export type MfaFactorFactory<Deps> = (deps: Deps) => Contributed<MfaFactor | null>;
/**
 * A `sessionRequirements` entry: a requirement every consumer of a browser
 * session asks through admission, keyed by its `name`. Never `null`: it is
 * switched off by not installing it, so nothing can quietly remove one from
 * behind the consumers. `reach` may be a getter, read after the name-keyed
 * pass, never at registration.
 */
export type SessionRequirementFactory<Deps> = (deps: Deps) => Contributed<SessionRequirement>;
export type AuditHookFactory<Deps> = (deps: Deps) => Contributed<AuditHook>;
export type GrantPolicyHookFactory<Deps> = (deps: Deps) => Contributed<GrantPolicyHookContribution>;

/**
 * Factory for the `discoveryMetadata` kind: the {@link OidcDiscoveryContribution}
 * a module wants advertised in `/.well-known/openid-configuration`.
 */
export type OidcDiscoveryContributionFactory<Deps> = (
	deps: Deps,
) => Contributed<OidcDiscoveryContribution>;

/**
 * Factory for the `grantMiddleware` kind: an Express `RequestHandler` mounted on
 * the token endpoint before grant dispatch, or `null` (never mounted) when
 * disabled by config.
 */
export type GrantMiddlewareFactory<Deps> = (deps: Deps) => Contributed<RequestHandler | null>;

/**
 * Factory for the `tokenBindingMechanisms` kind: a `TokenBindingMechanism`, or
 * `null` when disabled by config (e.g. `dpop.enabled = false`). Unlike
 * `grantMiddleware`, core composes ONE `tokenBindingMw` from every module's
 * mechanisms, so the configured `DispatchPolicy` arbitrates across modules.
 * See ADR 2026-05-20-token-binding-first-class-abstraction.
 */
export type TokenBindingMechanismFactory<Deps> = (
	deps: Deps,
) => Contributed<TokenBindingMechanism | null>;

/**
 * A `rateLimitBudgets` entry: the default limit and window for keys under one
 * rate-limit prefix the module owns, read from its own settings.
 *
 * Answer parsed numbers (through the module's schema, coercing environment
 * strings, or `requireUsableConfiguredRateLimitSpec`): the budget is held to
 * `isBoundedRateLimitSpec` as answered — a window of at most a year — and
 * `"20"` is not a limit.
 *
 * `null` claims the prefix with no budget of its own — keyed with none, or
 * switched off by the module's settings: absent from `rateLimitBudgetResolver`,
 * yet a second contribution is a duplicate. Absent is not unlimited: keys fall
 * to the limiter's `defaultLimit`. A module claims every prefix it keys.
 */
export type RateLimitBudgetFactory<Deps> = (deps: Deps) => Contributed<RateLimitSpec | null>;

/**
 * Declaration-merged map of contribution kinds. Packages and consumer plugins
 * add kinds via `declare module` (the session package adds
 * `federationRedirectPolicies`).
 *
 * Collisions:
 * - Name-keyed (`grants`, `tokenExchangeValidators`,
 *   `mfaFactors`, `sessionRequirements`, `rateLimitBudgets`,
 *   `federationTypes`, `admissionActions`): a duplicate refuses boot.
 * - List-shaped (`auditHooks`, `routes`, `grantPolicyHooks`,
 *   `grantMiddleware`): duplicates allowed; routes still refuse a duplicate
 *   `id` or an undecorated-mountPath collision.
 *
 * Every factory receives the declaring module's `requires` / `optional` Deps;
 * there is no per-contribution dep declaration.
 */
export interface ContributesMap<Deps = ProviderDeps<never, never>> {
	readonly grants?: { readonly [grantType: string]: GrantFactory<Deps> };
	/**
	 * Federation types, keyed by the `type` a `core.federations` entry names
	 * ({@link FederationTypeContribution}). Boot dispatches each enabled entry
	 * of a registered type to it, and registers the provider and redirect
	 * policy it builds under the entry's name: a federation registers this way
	 * alone, and a module contributing or overriding `federations` or
	 * `federationRedirectPolicies` refuses boot (`contribution-kind-guarded`). Two packages claiming one type refuse boot
	 * (`duplicate-contribute`); a declaration without an `entrySchema`, a
	 * `factory` and a `redirectPolicy` refuses it at stage 1
	 * (`contribution-malformed`); a host may not supply the collector
	 * (`contribution-kind-guarded`).
	 */
	readonly federationTypes?: {
		readonly [type: string]: FederationTypeContribution<Deps>;
	};
	readonly tokenExchangeValidators?: {
		readonly [tokenType: string]: ExchangeTokenValidatorFactory<Deps>;
	};
	readonly mfaFactors?: {
		readonly [kind: string]: MfaFactorFactory<Deps>;
	};
	/**
	 * Session requirements, name-keyed, projected by the synthetic key
	 * `sessionRequirementResolver` that every consumer of admission requires.
	 * Neither overridable (stage 1's `session-requirement-kind-guard`) nor
	 * replaceable by a host collector (`createApp`, before the kinds are merged).
	 */
	readonly sessionRequirements?: {
		readonly [name: string]: SessionRequirementFactory<Deps>;
	};
	/**
	 * Rate-limit budgets, keyed by the prefix a limiter key carries before its
	 * first `:` (`login` for `login:ip:<ip>`). Core composes every module's
	 * budgets into the synthetic key `rateLimitBudgetResolver`, read at request
	 * time. A prefix contributed twice refuses boot (`duplicate-contribute`); an
	 * empty prefix, one holding `:` or one naming an `Object.prototype` member
	 * refuses it at stage 1 (`contribution-malformed`); an unusable budget fails
	 * its contribution; a prefix is its claimant's, so an override of one, and a
	 * host's own collector, are refused (`contribution-kind-guarded`).
	 */
	readonly rateLimitBudgets?: {
		readonly [prefix: string]: RateLimitBudgetFactory<Deps>;
	};
	/**
	 * The actions this module admits through session admission, keyed by the
	 * name it passes `admitSession` (`acme.export`), each declaring one of
	 * core's grades. A declaration, not a factory: boot reads each once, at
	 * stage 1. A name outside the grammar, a grade outside the grades (or
	 * `remediation`, a requirement's), a container that is not a record and an
	 * override refuse it there (`contribution-malformed`); a name two modules
	 * register refuses it too (`duplicate-contribute`); a host may not supply
	 * the collector (`contribution-kind-guarded`).
	 */
	readonly admissionActions?: {
		readonly [name: string]: AdmissionActionDeclaration;
	};
	readonly auditHooks?: readonly AuditHookFactory<Deps>[];
	readonly routes?: readonly RouteContributionEntry<Deps>[];
	readonly grantPolicyHooks?: readonly GrantPolicyHookFactory<Deps>[];
	/**
	 * Express middleware mounted on the token endpoint (`/oauth/token` with the
	 * bundled `oauthModule`) BEFORE grant dispatch: token binding, custom rate
	 * limiters, body pre-processing. `null`-returning factories are skipped.
	 * List-shaped; mounted in module-registration order.
	 *
	 * Contributions compose as plain Express middleware: `tokenBindingMw` sets
	 * `req.tokenBinding` unconditionally, so a later contribution resolving a
	 * binding **overwrites** an earlier one. For deterministic dispatch across
	 * mechanisms, compose them into one `tokenBindingMw` (use
	 * `tokenBindingMechanisms`), where `DispatchPolicy` arbitrates.
	 */
	readonly grantMiddleware?: readonly GrantMiddlewareFactory<Deps>[];
	/**
	 * Token-binding mechanisms (DPoP, mTLS, ...), composed by core's
	 * `assembleApp` into one `tokenBindingMw` on the token endpoint, before grant
	 * dispatch. Use this, NOT `grantMiddleware`, for a mechanism. `null`s are
	 * dropped, and the `DispatchPolicy` from
	 * `config.core.tokenBinding.dispatchPolicy` arbitrates across modules.
	 * List-shaped; one module may contribute several. See ADR
	 * 2026-05-20-token-binding-first-class-abstraction.
	 */
	readonly tokenBindingMechanisms?: readonly TokenBindingMechanismFactory<Deps>[];
	/**
	 * OIDC discovery metadata. List-shaped: each endpoint-owning module supplies
	 * issuer-relative `endpoints` (e.g. `jwks_uri`) and literal `metadata`, and
	 * `assembleApp` merges them into `/.well-known/openid-configuration`
	 * (mounted only when an issuer is configured). The aggregator owns `issuer`
	 * and `id_token_signing_alg_values_supported`. Merge and validation rules:
	 * `core/src/discovery/buildDocument.mts`.
	 */
	readonly discoveryMetadata?: readonly OidcDiscoveryContributionFactory<Deps>[];
}
