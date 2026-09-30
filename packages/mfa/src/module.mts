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
 * Requires `config`, core's three MFA ports (the name `mfa` is accepted only from
 * a module bound to them), `userSessionStore` and `sessionRequirementResolver`;
 * reads `auditSink` (absence declared) and `logger`. Nothing forks per replica.
 *
 * Contributes `sessionRequirements.mfa`. Its factory refuses the boot when
 * `mfa.mode` is `off` or unset, when the package's settings are unusable (naming
 * the key), or when `endpoints.mfa.url` is unset. It builds the key ring's sealing
 * once per boot (so `mfa_factor_sealed_with_retired_key` is logged once per key
 * id) and keeps it, with the requirement core issues `mfa.step_up` to, for the
 * same boot's routes (`mfaBootState`). It warns once when the development sample
 * key is in use, and once when the user-session store cannot record a step-up
 * (`mfa_step_up_unsupported`); the requirement then sends the session to log in
 * instead.
 *
 * Contributes the `mfa-routes` mount at `/session/mfa`, after the session
 * middleware. Its factory runs after every factor has registered, so it checks
 * the installed factors (`checkInstalledFactors`). The routes themselves are not
 * implemented yet: the mount passes every request through.
 */

import {
	AUDIT_SINK_ABSENCE_POLICY,
	consoleLogger,
	defineModule,
	isHintToken,
	type Logger,
	type MfaFactorResolver,
	type Module,
	type SessionRequirement,
	type StepUpPage,
	supportsSecondFactorUpdate,
} from "@o3co/auth-provider-core";
import { type MfaSettings, mfaSectionSchema, readMfaSettings } from "./config.mjs";
import { createMfaRequirement, type MfaRequirementMode } from "./requirement.mjs";
import { createMfaSealing, type MfaSealing } from "./sealing.mjs";
import { mfaTotpFactorModule } from "./totp/module.mjs";
import { createLoginTransactions } from "./transactions.mjs";

/** The id of the MFA routes' contribution: what another route orders itself against. */
export const MFA_ROUTES_ID = "mfa-routes";

/** Where the MFA routes are mounted. */
const MFA_ROUTES_MOUNT_PATH = "/session/mfa";

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
 * (`HINT_LIST_MAX` in `session-admission/admit.mts`, which core does not
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

/** `deployment.mode` as the configuration carries it: the sample key's refusal reads it. */
const deploymentModeOf = (config: unknown): unknown =>
	(config as { deployment?: { mode?: unknown } } | undefined)?.deployment?.mode;

/** The page a step-up starts on: `endpoints.mfa.url`, which core's reference.conf defaults. */
function stepUpPageOf(config: unknown): StepUpPage {
	const url = (config as { endpoints?: { mfa?: { url?: unknown } } } | undefined)?.endpoints?.mfa
		?.url;
	if (typeof url !== "string" || url.length === 0) {
		throw new RangeError(
			"endpoints.mfa.url is not set: the MFA page a step-up starts on (ENDPOINTS_MFA_URL; core's reference.conf ships /mfa)",
		);
	}
	return { url, params: {} };
}

/** A route that answers nothing: every request passes through. */
const passThrough = (_req: unknown, _res: unknown, next: () => void): void => next();

/**
 * The MFA module (see this file's header): the `mfa` session requirement and
 * the MFA routes' mount. `options.environment` reaches the development
 * sample key's refusal.
 */
export function mfaModule(options: MfaModuleOptions = {}): Module {
	return defineModule<
		| "config"
		| "mfaFactorResolver"
		| "mfaFactorStore"
		| "mfaTransactionStore"
		| "userSessionStore"
		| "sessionRequirementResolver",
		"auditSink" | "logger",
		typeof mfaSectionSchema
	>({
		name: "mfa",
		// The module's own section, read at its name. Its schema holds the mode
		// to its three values before any factory runs; the requirement's
		// factory reads the rest (`readMfaSettings`), and what that refuses
		// stays the factory's failure.
		section: {
			schema: mfaSectionSchema,
			reference: new URL("../config/reference.conf", import.meta.url),
		},
		requires: [
			"config",
			"mfaFactorResolver",
			"mfaFactorStore",
			"mfaTransactionStore",
			"userSessionStore",
			"sessionRequirementResolver",
		],
		optional: ["auditSink", "logger"],
		absencePolicies: { auditSink: AUDIT_SINK_ABSENCE_POLICY },
		contributes: {
			sessionRequirements: {
				mfa: (deps) => {
					const mode = deps.section?.mode ?? "off";
					if (mode === "off") {
						throw new RangeError(
							'mfa.mode is "off" (or unset) while the MFA module is installed: remove the MFA module, or set mfa.mode to "required" or "optional"',
						);
					}
					const settings = readMfaSettings(deps.section, {
						...options,
						deploymentMode: deploymentModeOf(deps.config),
					});
					const stepUpPage = stepUpPageOf(deps.config);
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
						logger,
					});
					bootStates.set(deps.mfaFactorResolver, {
						mode,
						settings,
						sealing: createMfaSealing({ ring: settings.encryptionKeys, logger }),
						requirement,
						logger,
					});
					return requirement;
				},
			},
			routes: [
				(deps) => {
					const { mode } = mfaBootState(deps.mfaFactorResolver);
					checkInstalledFactors(deps.mfaFactorResolver, mode);
					return {
						id: MFA_ROUTES_ID,
						mountPath: MFA_ROUTES_MOUNT_PATH,
						after: ["session-middleware"],
						handler: passThrough,
					};
				},
			],
		},
	});
}

/** What a composition lists to install MFA: the TOTP factor's module and the MFA module. */
export function mfaModules(options: MfaModuleOptions = {}): readonly Module[] {
	return [mfaTotpFactorModule, mfaModule(options)];
}
