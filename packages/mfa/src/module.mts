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

/**
 * `mfaModule` and `mfaModules`: what a composition installs to turn MFA on
 * (installed is on).
 *
 * Requires core's three MFA ports (the name `mfa` is accepted only from a
 * module bound to them), `userSessionStore`, `sessionRequirementResolver`,
 * `csrfGuard` (every MFA POST runs it), `loginCompletion` (a verified second
 * factor finishes the login through it) and `deploymentMode` (the development
 * sample key and the routes' per-process limiter are refused under `multi`,
 * so a mode read as absent must not lift that); reads `rateLimiter`,
 * `auditSink` and `subjectRevocation` (each absence declared; the routes'
 * admission of a signed-in session reads the boundary), `logger`,
 * `mailSender` — where the account-email proof and a factor's codes go — and
 * `userRepository`, for the enrollment witness's write alone
 * (`markMfaEnrolled`). Nothing it keeps forks per replica; without a shared
 * `rateLimiter` its routes' limiter does, refused under `multi`, warned about
 * when the mode is unset.
 *
 * Reads its own section, `mfa` — the mode, its settings and the step-up
 * page, `mfa.page.url` — and the deployment mode from the `deploymentMode`
 * slot. The page's old path, `endpoints.mfa.url`, refuses the boot naming
 * the new one, and so does `ENDPOINTS_MFA_URL` unless `MFA_PAGE_URL` carries
 * the same value.
 *
 * Contributes `sessionRequirements.mfa`. Its factory refuses the boot when
 * `mfa.mode` is `off` or unset, when the package's settings are unusable (naming
 * the key), when `mfa.page.url` is unset, or when
 * `mfa.enrollment.requireEmailProof` is `always` and no `mailSender` is wired —
 * nobody could give the proof, so nobody could bind (the MFA ADR's D20). It
 * builds the key ring's sealing once per boot (so
 * `mfa_factor_sealed_with_retired_key` is logged once per key id) and keeps it,
 * with the requirement core issues `mfa.step_up` to and the enrollment
 * witness, for the same boot's routes (`mfaBootState`). It warns once each:
 * when the development sample key is in use; when the user-session store
 * cannot record a step-up (`mfa_step_up_unsupported`), the requirement then
 * sending the session to log in instead; when `when-mail` meets no
 * `mailSender`, so a first binding asks no proof
 * (`mfa_first_binding_without_email_proof`); and when the directory cannot
 * write the witness (`mfa_enrollment_witness_unwritable`).
 *
 * Contributes `mfa.rateLimit.routes` as the budget of the `mfa` prefix every
 * `/session/mfa` POST limits under, for every limiter to read; none when the
 * section gives none.
 *
 * Contributes `mfa.manage`, graded `credential_change`, as the admission
 * action its routes admit a signed-in session's enrollment for.
 *
 * Contributes the MFA routes (`routes.mts`) at `/session/mfa`, after the
 * session middleware. Their factory runs after every factor has registered,
 * so it checks the installed factors (`checkInstalledFactors`) first, and
 * the resolver holds `mfa.manage` (core's `checkResolver`).
 */

import {
	AUDIT_SINK_ABSENCE_POLICY,
	type AuditSink,
	BootError,
	checkDeploymentMode,
	checkResolver,
	consoleLogger,
	createMemoryRateLimiter,
	createRateLimitGuard,
	type DeploymentMode,
	defineModule,
	isHintToken,
	issuedRemediationActions,
	type Logger,
	type MfaFactorResolver,
	type Module,
	type RateLimiter,
	type RateLimitSpec,
	requireUsableConfiguredRateLimitSpec,
	type SessionRequirement,
	type StepUpPage,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
	supportsSecondFactorUpdate,
} from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import { MFA_ADMISSION_ACTIONS } from "./admissionActions.mjs";
import { type MfaMode, type MfaSettings, mfaSectionSchema, readMfaSettings } from "./config.mjs";
import { createMfaCoordinator } from "./coordinator.mjs";
import { mfaEmailFactorModule } from "./email/module.mjs";
import { mfaRecoveryCodeFactorModule } from "./recovery/module.mjs";
import { createMfaRequirement, type MfaRequirementMode } from "./requirement.mjs";
import { createMfaRouter } from "./routes.mjs";
import { createMfaSealing, type MfaSealing } from "./sealing.mjs";
import { mfaTotpFactorModule } from "./totp/module.mjs";
import { createLoginTransactions } from "./transactions.mjs";
import { createMfaEnrollmentWitness, type MfaEnrollmentWitness } from "./witness.mjs";

/** The id of the MFA routes' contribution: what another route orders itself against. */
export const MFA_ROUTES_ID = "mfa-routes";

/** Where the MFA routes are mounted. */
const MFA_ROUTES_MOUNT_PATH = "/session/mfa";

/**
 * The key prefix every `/session/mfa` POST limits under (`mfa:ip:<ip>`), the
 * flood guard of ADR 2026-09-25-multi-factor-authentication. No `:`.
 */
export const MFA_RATE_LIMIT_PREFIX = "mfa";

/**
 * `mfa.rateLimit.routes` as the MFA routes' budget, `null` when not given;
 * read as a coercing schema reads it, and a `RangeError` naming the key when
 * no limiter can apply it.
 */
function routesBudget(section: unknown): RateLimitSpec | null {
	const given = (section as { rateLimit?: { routes?: unknown } } | null | undefined)?.rateLimit
		?.routes;
	if (given === undefined) return null;
	return requireUsableConfiguredRateLimitSpec("mfa.rateLimit.routes", given);
}

/** What a composition root tells the MFA module that its configuration cannot. */
export interface MfaModuleOptions {
	/**
	 * The name the deployment selected its configuration by — the standalone
	 * passes `CONFIG_ENV || NODE_ENV` — read beside `NODE_ENV` by the
	 * development sample key's refusal.
	 */
	readonly environment?: string;
}

/** What one boot of the MFA module built, for the routes of the same boot. */
export interface MfaBootState {
	readonly mode: MfaRequirementMode;
	readonly settings: MfaSettings;
	/** The one sealing of this boot, on the composition's logger. */
	readonly sealing: MfaSealing;
	/** The object the requirement's factory returned: the one core issued `mfa.step_up` to. */
	readonly requirement: SessionRequirement;
	/** The enrollment witness over the composition's directory. */
	readonly witness: MfaEnrollmentWitness;
	readonly logger: Logger;
}

/**
 * Each boot's state, keyed by that boot's `mfaFactorResolver`. Relies on core
 * handing the same projection object to both factories of a boot and a new one
 * to every boot (`prepareSyntheticProjections` in core's
 * `boot/apply-contributions.mts`); `module.test.mts` pins both.
 */
const bootStates = new WeakMap<object, MfaBootState>();

/**
 * What the MFA module built in the boot whose `mfaFactorResolver` is
 * `factors`. Throws when that boot built none: the requirement's factory
 * runs before any route factory, so a route asking for it is in a boot
 * without the module.
 */
export function mfaBootState(factors: MfaFactorResolver): MfaBootState {
	const state = bootStates.get(factors);
	if (state === undefined) {
		throw new Error("the MFA module built nothing in this boot: install mfaModule");
	}
	return state;
}

/**
 * `mfa.mode = "required"` with no counting factor enabled: the `cause` of the
 * boot's refusal, with its reason.
 */
export class MfaNoCountingFactorError extends RangeError {
	readonly reason = "mfa-no-counting-factor";

	/**
	 * `enabledKinds`: the enabled factors, none counting, already admitted by core's
	 * hint grammar. The module cannot tell which factor modules are installed, so the
	 * message names the TOTP key only conditionally.
	 */
	constructor(enabledKinds: readonly string[]) {
		const enabled =
			enabledKinds.length === 0
				? "no factor is enabled"
				: `the enabled factors (${enabledKinds.join(", ")}) do not count`;
		super(
			`mfa.mode is "required", but ${enabled}, so nobody could meet the requirement: enable an installed counting factor through its module's \`enabled\` key — for the TOTP factor, when mfaTotpFactorModule is installed, mfa-totp-factor.enabled (MFA_TOTP_FACTOR_ENABLED) — or set mfa.mode = "optional"`,
		);
		this.name = "MfaNoCountingFactorError";
	}
}

/**
 * An enabled factor whose kind core's hint grammar refuses: a first
 * binding's answer lists the kinds (`hints.enrollable`), and core would
 * refuse that answer at every such login. The `cause` of the boot's
 * refusal; `JSON.stringify` quotes the kind, whatever it holds.
 */
export class MfaFactorKindUnhintableError extends RangeError {
	readonly reason = "mfa-factor-kind-unhintable";

	constructor(kind: string) {
		super(
			`the MFA factor of kind ${JSON.stringify(kind)} cannot be offered: a first binding's hints.enrollable names each kind, and core admits a hint only of the form ^[a-z][a-z0-9_-]{0,63}$ — contribute the factor under such a kind`,
		);
		this.name = "MfaFactorKindUnhintableError";
	}
}

/**
 * The most kinds a hint list carries: core's cap on a hint's list
 * (`HINT_LIST_MAX` in `session-admission/interruption-answer.mts`, which core does not
 * export; `module.test.mts` holds the two to each other).
 */
const HINT_LIST_MAX = 16;

/**
 * More enabled counting factors than a hint list carries: a first binding's
 * `hints.enrollable` would list them all, and core would refuse that answer
 * at every such login. The `cause` of the boot's refusal.
 */
export class MfaTooManyFactorsError extends RangeError {
	readonly reason = "mfa-too-many-factors";

	constructor(count: number) {
		super(
			`${count} counting MFA factors are enabled, and a first binding's hints.enrollable lists at most ${HINT_LIST_MAX}, as core admits a hint list of no more: enable ${HINT_LIST_MAX} or fewer`,
		);
		this.name = "MfaTooManyFactorsError";
	}
}

/**
 * What the requirement needs of the installed factors, checked once they
 * have all registered: every kind one a hint can carry, no more counting
 * factors than a hint list carries, and — under `required` — at least one.
 */
function checkInstalledFactors(factors: MfaFactorResolver, mode: MfaRequirementMode): void {
	const installed = [...factors.entries()];
	for (const [kind] of installed) {
		if (!isHintToken(kind)) throw new MfaFactorKindUnhintableError(kind);
	}
	const counting = installed.filter(([, factor]) => factor.counting).length;
	if (counting > HINT_LIST_MAX) throw new MfaTooManyFactorsError(counting);
	if (mode === "required" && counting === 0) {
		throw new MfaNoCountingFactorError(installed.map(([kind]) => kind));
	}
}

/** The page a step-up starts on: `mfa.page.url`, which the package's reference.conf defaults. */
function stepUpPageOf(section: unknown): StepUpPage {
	const url = (section as { page?: { url?: unknown } } | null | undefined)?.page?.url;
	if (typeof url !== "string" || url.length === 0) {
		throw new RangeError(
			"mfa.page.url is not set: the MFA page a step-up starts on (MFA_PAGE_URL; the package's reference.conf ships /mfa)",
		);
	}
	return { url, params: {} };
}

/**
 * The guard every MFA POST runs, under the `mfa` prefix: over the shared
 * `rateLimiter`, or — with none wired — a per-process limiter over `budget`,
 * which several replicas would each count apart: refused under `multi`,
 * said once at warn when the mode is unset.
 */
function mfaFloodGuard(options: {
	readonly rateLimiter: RateLimiter | undefined;
	readonly budget: RateLimitSpec | null;
	readonly deploymentMode: DeploymentMode;
	readonly logger: Logger;
	readonly auditSink: AuditSink | undefined;
}): RequestHandler {
	const { budget, logger, auditSink } = options;
	let limiter = options.rateLimiter;
	if (limiter === undefined) {
		if (budget === null) {
			throw new RangeError(
				"mfa.rateLimit.routes is not set and no rateLimiter is wired: the MFA routes would run unlimited (the package's reference.conf ships 60 per 300 s)",
			);
		}
		const replicas = checkDeploymentMode(options.deploymentMode, "mfa routes: deploymentMode");
		if (replicas === "multi") {
			throw new BootError({
				stage: "applyContributions",
				reason: "replica-unsafe-adapter",
				message: `core.deployment.mode is "multi" but no shared rateLimiter is wired for the MFA routes: each replica would count ${budget.limit} per ${budget.windowSeconds}s apart, so the limit is really ${budget.limit} times the replicas. Wire a shared rateLimiter (adapters.rateLimiter = "redis" in the standalone template), or set core.deployment.mode = "single".`,
				details: { reason: "replica-unsafe-adapter", modules: ["mfa"] },
			});
		}
		if (replicas !== "single") {
			logger.warn(
				{ limit: budget.limit, windowSeconds: budget.windowSeconds },
				"mfa_rate_limiter_not_shared",
			);
		}
		limiter = createMemoryRateLimiter({
			limits: { [MFA_RATE_LIMIT_PREFIX]: budget },
			defaultLimit: budget,
		});
	}
	return createRateLimitGuard({
		limiter,
		tag: MFA_RATE_LIMIT_PREFIX,
		logger,
		...(auditSink === undefined ? {} : { auditSink }),
		...(budget === null ? {} : { headerFallback: budget }),
	});
}

/**
 * The MFA module (see this file's header): the `mfa` session requirement and
 * the MFA routes' mount. `options.environment` reaches the development
 * sample key's refusal.
 */
export function mfaModule(options: MfaModuleOptions = {}): Module {
	return defineModule<
		| "mfaFactorResolver"
		| "mfaFactorStore"
		| "mfaTransactionStore"
		| "userSessionStore"
		| "sessionRequirementResolver"
		| "csrfGuard"
		| "loginCompletion"
		| "deploymentMode",
		"rateLimiter" | "auditSink" | "subjectRevocation" | "logger" | "mailSender" | "userRepository",
		typeof mfaSectionSchema
	>({
		name: "mfa",
		// The module's own section, read at its name. Its schema holds the mode
		// to its three values and the page to its shape before any factory
		// runs; the requirement's factory reads the settings (`readMfaSettings`)
		// and the page (`stepUpPageOf`), and what those refuse stays the
		// factory's failure.
		section: {
			schema: mfaSectionSchema,
			reference: new URL("../config/reference.conf", import.meta.url),
			relocatedFrom: { "endpoints.mfa.url": "page.url" },
			renamedVariables: { ENDPOINTS_MFA_URL: "endpoints.mfa.url" },
		},
		requires: [
			"mfaFactorResolver",
			"mfaFactorStore",
			"mfaTransactionStore",
			"userSessionStore",
			"sessionRequirementResolver",
			"csrfGuard",
			"loginCompletion",
			"deploymentMode",
		],
		optional: [
			"rateLimiter",
			"auditSink",
			"subjectRevocation",
			"logger",
			"mailSender",
			"userRepository",
		],
		absencePolicies: {
			auditSink: AUDIT_SINK_ABSENCE_POLICY,
			subjectRevocation: SUBJECT_REVOCATION_ABSENCE_POLICY,
		},
		contributes: {
			admissionActions: MFA_ADMISSION_ACTIONS,
			rateLimitBudgets: {
				[MFA_RATE_LIMIT_PREFIX]: (deps) => routesBudget(deps.section),
			},
			sessionRequirements: {
				mfa: (deps) => {
					const mode: MfaMode = deps.section?.mode ?? "off";
					if (mode === "off") {
						throw new RangeError(
							'mfa.mode is "off" (or unset) while the MFA module is installed: remove the MFA module, or set mfa.mode to "required" or "optional"',
						);
					}
					const settings = readMfaSettings(deps.section, {
						...options,
						deploymentMode: deps.deploymentMode,
					});
					const stepUpPage = stepUpPageOf(deps.section);
					const logger = deps.logger ?? consoleLogger;
					if (settings.developmentSampleKeyAccepted) {
						logger.warn(
							{ setting: "mfa.encryptionKeys", variable: "MFA_ENCRYPTION_KEY" },
							"mfa_development_sample_key_in_use",
						);
					}
					// A session store that cannot record a step-up is warned about once; the
					// requirement then sends a session to log in where it would step it up.
					const stepUpRecordable = supportsSecondFactorUpdate(deps.userSessionStore);
					if (!stepUpRecordable) {
						logger.warn(
							{ store: "userSessionStore", kind: deps.userSessionStore.kind },
							"mfa_step_up_unsupported",
						);
					}
					// D20: under "always" nobody could give the proof without a sender, so
					// nobody could bind; under "when-mail" a first binding goes without it.
					const { requireEmailProof } = settings.enrollment;
					const mailWired = deps.mailSender !== undefined;
					if (requireEmailProof === "always" && !mailWired) {
						throw new RangeError(
							'mfa.enrollment.requireEmailProof is "always" and no mail sender is wired: nobody could give the account-email proof, so nobody could bind a factor — wire a mail sender, or set mfa.enrollment.requireEmailProof (MFA_ENROLLMENT_REQUIRE_EMAIL_PROOF) to "when-mail" or "never"',
						);
					}
					if (requireEmailProof === "when-mail" && !mailWired) {
						logger.warn(
							{ setting: "mfa.enrollment.requireEmailProof", value: requireEmailProof },
							"mfa_first_binding_without_email_proof",
						);
					}
					// A directory that cannot write the witness leaves D12's defence to
					// what the Store answers on authenticate: said once.
					const witness = createMfaEnrollmentWitness(deps.userRepository);
					if (!witness.writable) {
						logger.warn({ slot: "userRepository" }, "mfa_enrollment_witness_unwritable");
					}
					const requirement = createMfaRequirement({
						mode,
						factors: deps.mfaFactorResolver,
						factorStore: deps.mfaFactorStore,
						transactions: createLoginTransactions({
							store: deps.mfaTransactionStore,
							ttlSeconds: settings.transactionTtlSeconds,
						}),
						stepUpPage,
						stepUpRecordable,
						recentMfaMaxAgeSeconds: settings.manage.maxAgeSeconds,
						logger,
						auditSink: deps.auditSink,
						firstBinding: { requireEmailProof, mailWired },
						emailProofRequiredAtNextBinding: (subject) =>
							deps.mfaTransactionStore.emailProofRequiredAtNextBinding(subject),
						sessionEmailProofAt: (subject, sid, nowMs) =>
							deps.mfaTransactionStore.sessionEmailProofAt(subject, sid, nowMs),
					});
					bootStates.set(deps.mfaFactorResolver, {
						mode,
						settings,
						sealing: createMfaSealing({ ring: settings.encryptionKeys, logger }),
						requirement,
						witness,
						logger,
					});
					return requirement;
				},
			},
			routes: [
				(deps) => {
					const { mode, settings, sealing, requirement, witness, logger } = mfaBootState(
						deps.mfaFactorResolver,
					);
					checkInstalledFactors(deps.mfaFactorResolver, mode);
					const requirements = checkResolver(
						deps.sessionRequirementResolver,
						"mfaModule",
						Object.keys(MFA_ADMISSION_ACTIONS),
					);
					const stepUp = issuedRemediationActions(requirement)?.step_up;
					if (stepUp === undefined) {
						throw new Error("core issued the mfa requirement no mfa.step_up remediation");
					}
					return {
						id: MFA_ROUTES_ID,
						mountPath: MFA_ROUTES_MOUNT_PATH,
						after: ["session-middleware"],
						handler: createMfaRouter({
							coordinator: createMfaCoordinator({
								factors: deps.mfaFactorResolver,
								factorStore: deps.mfaFactorStore,
								transactions: deps.mfaTransactionStore,
								sealing,
								maxAttemptsPerTransaction: settings.maxAttemptsPerTransaction,
								mode,
								mailSender: deps.mailSender,
								witness,
								transactionTtlSeconds: settings.transactionTtlSeconds,
								maxFactorsPerSubject: settings.maxFactorsPerSubject,
								sessionProofSeconds: settings.manage.maxAgeSeconds,
							}),
							admission: {
								userSessionStore: deps.userSessionStore,
								subjectRevocation: deps.subjectRevocation,
								requirements,
								acrTable: {},
								logger,
								auditSink: deps.auditSink,
							},
							stepUp,
							loginCompletion: deps.loginCompletion,
							csrfGuard: deps.csrfGuard,
							floodGuard: mfaFloodGuard({
								rateLimiter: deps.rateLimiter,
								budget: routesBudget(deps.section),
								deploymentMode: deps.deploymentMode,
								logger,
								auditSink: deps.auditSink,
							}),
							logger,
							auditSink: deps.auditSink,
						}),
					};
				},
			],
		},
	});
}

/**
 * What a composition lists to install MFA: the TOTP factor's module, the
 * recovery-code factor's, the email factor's (off by default), and the MFA
 * module.
 */
export function mfaModules(options: MfaModuleOptions = {}): readonly Module[] {
	return [
		mfaTotpFactorModule,
		mfaRecoveryCodeFactorModule,
		mfaEmailFactorModule,
		mfaModule(options),
	];
}
