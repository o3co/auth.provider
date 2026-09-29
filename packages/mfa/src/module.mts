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
 * `mfaModule` and `mfaModules` (the MFA ADR's D1, D11, D20 and step 3's
 * obligations; the session-admission ADR's D3, D6, D7): what a composition
 * installs to turn MFA on — installed is on.
 *
 * - **Manifest.** Requires `config`, core's three MFA ports
 *   (`mfaFactorResolver`, `mfaFactorStore`, `mfaTransactionStore`) — the
 *   name `mfa` is accepted only from a module bound to them — the
 *   `userSessionStore` (a composition without one is refused at the
 *   requires-closure, naming the slot) and `sessionRequirementResolver`;
 *   reads `auditSink`, its absence declared (`audit.sink.type = "none"`), and
 *   `logger`. Stateless: nothing forks per replica.
 * - **The requirement.** Contributes `sessionRequirements.mfa`
 *   (`requirement.mts`). Its factory reads, in order: `mfa.mode` through
 *   core's `readMfaMode` — `off`, or unset, is refused ("remove the MFA
 *   module, or set `mfa.mode`", D20); the package's settings
 *   (`readMfaSettings`, with the module's `environment`), so a ring, a
 *   transaction life or a lock it cannot use refuses the boot, naming the
 *   key; `endpoints.mfa.url`, the page a step-up starts on. It builds, once
 *   per boot, the key ring's sealing on the composition's logger — what
 *   keeps `mfa_factor_sealed_with_retired_key` to once per key id — and the
 *   requirement, and keeps both, with the object it returned — the one core
 *   issues `mfa.step_up` to (build-order step 11) — for the routes of the
 *   same boot (`mfaBootState`). When the ring carries the development sample
 *   key, which the settings accepted, it says so once, at warn; so it does
 *   when the user-session store cannot record a step-up
 *   (`mfa_step_up_unsupported`, core's `supportsSecondFactorUpdate`, D20),
 *   and the requirement then sends a session to log in where it would step
 *   it up.
 * - **The routes' mount.** Contributes the route `mfa-routes` at
 *   `/session/mfa`, after the session middleware. Its factory runs after
 *   every name-keyed contribution has registered, so it is where the
 *   installed factors are held to what the requirement needs of them, each
 *   refusal a `cause` with a `reason`: an enabled factor whose kind core's
 *   hint grammar refuses — a first binding's `hints.enrollable` names it —
 *   (`mfa-factor-kind-unhintable`, naming the kind); more enabled counting
 *   factors than core's hint list carries, 16 (`mfa-too-many-factors`); and
 *   `mfa.mode = "required"` with no counting factor enabled
 *   (`mfa-no-counting-factor`, D20): nobody could meet the requirement. The
 *   routes themselves — the transaction, the challenge, the verification —
 *   are build-order step 8's third part; until then it answers nothing and
 *   every request passes through.
 *
 * `mfaModules` is what a composition lists: the TOTP factor's module and
 * this one.
 */

import {
	AUDIT_SINK_ABSENCE_POLICY,
	consoleLogger,
	defineModule,
	isHintToken,
	type Logger,
	type MfaFactorResolver,
	type Module,
	readMfaMode,
	type SessionRequirement,
	type StepUpPage,
	supportsSecondFactorUpdate,
} from "@o3co/auth-provider-core";
import { type MfaSettings, readMfaSettings } from "./config.mjs";
import { createMfaRequirement, type MfaRequirementMode } from "./requirement.mjs";
import { createMfaSealing, type MfaSealing } from "./sealing.mjs";
import { mfaTotpFactorModule } from "./totp/module.mjs";
import { createLoginTransactions } from "./transactions.mjs";

/** The id of the MFA routes' contribution: what another route orders itself against. */
export const MFA_ROUTES_ID = "mfa-routes";

/** Where the MFA routes are mounted (the MFA ADR's §2). */
const MFA_ROUTES_MOUNT_PATH = "/session/mfa";

/** What a composition root tells the MFA module that its configuration cannot (#473). */
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
 * Each boot's state, by that boot's `mfaFactorResolver`: a projection core
 * builds once per boot and hands every factory of it, the requirement's and
 * the routes' alike.
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
 * `mfa.mode = "required"` with no counting factor enabled (the MFA ADR's
 * D20): the `cause` of the boot's refusal, with its reason.
 */
export class MfaNoCountingFactorError extends RangeError {
	readonly reason = "mfa-no-counting-factor";

	constructor() {
		super(
			'mfa.mode is "required", but no counting factor is enabled, so nobody could meet the requirement: enable one — mfa.factors.totp.enabled (MFA_TOTP_ENABLED), or another factor module\'s — or set mfa.mode = "optional"',
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
	if (mode === "required" && counting === 0) throw new MfaNoCountingFactorError();
}

/** The page a step-up starts on: `endpoints.mfa.url` (D19), which core's reference.conf defaults. */
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

/** A route that answers nothing: every request passes through, until the MFA routes land. */
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
		"auditSink" | "logger"
	>({
		name: "mfa",
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
					const mode = readMfaMode(deps.config) ?? "off";
					if (mode === "off") {
						throw new RangeError(
							'mfa.mode is "off" (or unset) while the MFA module is installed: remove the MFA module, or set mfa.mode to "required" or "optional"',
						);
					}
					const settings = readMfaSettings(deps.config, options);
					const stepUpPage = stepUpPageOf(deps.config);
					const logger = deps.logger ?? consoleLogger;
					if (settings.developmentSampleKeyAccepted) {
						logger.warn(
							{ setting: "mfa.encryptionKeys", variable: "MFA_ENCRYPTION_KEY" },
							"mfa_development_sample_key_in_use",
						);
					}
					// D20: a session store that cannot record a step-up is said once;
					// the requirement then sends a session to log in where it would
					// step it up.
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
