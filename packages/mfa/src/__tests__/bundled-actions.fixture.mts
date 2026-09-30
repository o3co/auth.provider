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
 * The actions the bundled consumers admit, each with the grade its package
 * registers and the carrier its consumer reads the session by, and the verdicts
 * the MFA requirement answers for each. The MFA package's equivalence test
 * holds the requirement to these verdicts over these grades; `tools/composition`
 * holds the full set's registrations to these grades.
 */

import type { ActionGrade, SessionClaim } from "@o3co/auth-provider-core";

export interface BundledAction {
	readonly grade: ActionGrade;
	readonly carrier: SessionClaim["carrier"];
}

/** Every action a bundled consumer admits, by name. */
export const BUNDLED_ACTIONS: Readonly<Record<string, BundledAction>> = {
	"oauth.authorize": { grade: "use", carrier: "cookie" },
	"oauth.consent": { grade: "use", carrier: "cookie" },
	"oauth.session_grant": { grade: "use", carrier: "cookie" },
	"oauth.code_exchange": { grade: "use", carrier: "code" },
	"oauth.refresh": { grade: "use", carrier: "token" },
	"device.lookup": { grade: "grants_nothing", carrier: "cookie" },
	"device.approve": { grade: "use", carrier: "cookie" },
	"device.deny": { grade: "grants_nothing", carrier: "cookie" },
	"federation_grants.connect": { grade: "use", carrier: "cookie" },
	"federation_grants.consent": { grade: "use", carrier: "cookie" },
	"federation_grants.callback": { grade: "use", carrier: "cookie" },
	"session.link": { grade: "credential_change", carrier: "cookie" },
	"session.link_callback": { grade: "use", carrier: "link" },
	"webauthn.register": { grade: "credential_change", carrier: "cookie" },
	"mfa.manage": { grade: "credential_change", carrier: "cookie" },
};

/**
 * The sessions a cookie, code or link carries, in the order a verdict string
 * lists them: none, a password login without a second factor, one with
 * `mfaAt`, a federated one, one whose primary cannot be told, and one whose
 * primary the baseline does not know — each signed in, and its second factor
 * verified where it has one, a minute before admission's clock, inside recent
 * MFA's window — then a password login without a second factor signed in a
 * day before, outside it.
 */
export const SESSION_SITUATIONS = [
	"none",
	"pwd",
	"pwd+mfaAt",
	"fed",
	"untold",
	"unknown primary",
	"pwd, stale",
] as const;

/** The `amr` a token carries, in the order a verdict string lists them. */
export const TOKEN_SITUATIONS: readonly (readonly string[] | undefined)[] = [
	["pwd"],
	undefined,
	[],
	["hwk"],
	["fed"],
	["pwd", "otp", "mfa"],
	["mfa"],
	["pwd", "email"],
];

/**
 * The setups a verdict table is taken under: the factors installed, whether
 * the session store can record a step-up, and the kinds of the factor records
 * the subject holds.
 */
export const SETUPS = {
	"totp, recordable": { factors: ["totp"], stepUpRecordable: true, holds: [] },
	"no factor": { factors: [], stepUpRecordable: true, holds: [] },
	"totp, not recordable": { factors: ["totp"], stepUpRecordable: false, holds: [] },
	"totp, recordable, holding totp": {
		factors: ["totp"],
		stepUpRecordable: true,
		holds: ["totp"],
	},
} as const;

/**
 * The verdicts, one letter per situation — `m` met, `r` reauthenticate, `s`
 * step_up (sent to log in again when still unmet), `u` unmet — by mode and
 * setup, then by action.
 */
export const VERDICTS: Readonly<Record<string, Readonly<Record<string, string>>>> = {
	"optional · totp, recordable": {
		"oauth.authorize": "mmmmmmm",
		"oauth.consent": "mmmmmmm",
		"oauth.session_grant": "mmmmmmm",
		"oauth.code_exchange": "mmmmmmm",
		"oauth.refresh": "mmmmmmmm",
		"device.lookup": "mmmmmmm",
		"device.approve": "mmmmmmm",
		"device.deny": "mmmmmmm",
		"federation_grants.connect": "mmmmmmm",
		"federation_grants.consent": "mmmmmmm",
		"federation_grants.callback": "mmmmmmm",
		"session.link": "rmmmrrr",
		"session.link_callback": "mmmmmmm",
		"webauthn.register": "rmmmrrr",
		"mfa.manage": "rmmmrrr",
	},
	"optional · no factor": {
		"oauth.authorize": "mmmmmmm",
		"oauth.consent": "mmmmmmm",
		"oauth.session_grant": "mmmmmmm",
		"oauth.code_exchange": "mmmmmmm",
		"oauth.refresh": "mmmmmmmm",
		"device.lookup": "mmmmmmm",
		"device.approve": "mmmmmmm",
		"device.deny": "mmmmmmm",
		"federation_grants.connect": "mmmmmmm",
		"federation_grants.consent": "mmmmmmm",
		"federation_grants.callback": "mmmmmmm",
		"session.link": "rmmmrrr",
		"session.link_callback": "mmmmmmm",
		"webauthn.register": "rmmmrrr",
		"mfa.manage": "rmmmrrr",
	},
	"optional · totp, not recordable": {
		"oauth.authorize": "mmmmmmm",
		"oauth.consent": "mmmmmmm",
		"oauth.session_grant": "mmmmmmm",
		"oauth.code_exchange": "mmmmmmm",
		"oauth.refresh": "mmmmmmmm",
		"device.lookup": "mmmmmmm",
		"device.approve": "mmmmmmm",
		"device.deny": "mmmmmmm",
		"federation_grants.connect": "mmmmmmm",
		"federation_grants.consent": "mmmmmmm",
		"federation_grants.callback": "mmmmmmm",
		"session.link": "rmmmrrr",
		"session.link_callback": "mmmmmmm",
		"webauthn.register": "rmmmrrr",
		"mfa.manage": "rmmmrrr",
	},
	"required · totp, recordable": {
		"oauth.authorize": "rsmmrrs",
		"oauth.consent": "rsmmrrs",
		"oauth.session_grant": "rsmmrrs",
		"oauth.code_exchange": "rsmmrrs",
		"oauth.refresh": "urrmmmrm",
		"device.lookup": "rmmmmmm",
		"device.approve": "rsmmrrs",
		"device.deny": "rmmmmmm",
		"federation_grants.connect": "rsmmrrs",
		"federation_grants.consent": "rsmmrrs",
		"federation_grants.callback": "rsmmrrs",
		"session.link": "rsmmrrs",
		"session.link_callback": "rsmmrrs",
		"webauthn.register": "rsmmrrs",
		"mfa.manage": "rsmmrrs",
	},
	"required · no factor": {
		"oauth.authorize": "rummrru",
		"oauth.consent": "rummrru",
		"oauth.session_grant": "rummrru",
		"oauth.code_exchange": "rummrru",
		"oauth.refresh": "urrmmmrm",
		"device.lookup": "rmmmmmm",
		"device.approve": "rummrru",
		"device.deny": "rmmmmmm",
		"federation_grants.connect": "rummrru",
		"federation_grants.consent": "rummrru",
		"federation_grants.callback": "rummrru",
		"session.link": "rummrru",
		"session.link_callback": "rummrru",
		"webauthn.register": "rummrru",
		"mfa.manage": "rummrru",
	},
	"required · totp, not recordable": {
		"oauth.authorize": "rrmmrrr",
		"oauth.consent": "rrmmrrr",
		"oauth.session_grant": "rrmmrrr",
		"oauth.code_exchange": "rrmmrrr",
		"oauth.refresh": "urrmmmrm",
		"device.lookup": "rmmmmmm",
		"device.approve": "rrmmrrr",
		"device.deny": "rmmmmmm",
		"federation_grants.connect": "rrmmrrr",
		"federation_grants.consent": "rrmmrrr",
		"federation_grants.callback": "rrmmrrr",
		"session.link": "rrmmrrr",
		"session.link_callback": "rrmmrrr",
		"webauthn.register": "rrmmrrr",
		"mfa.manage": "rrmmrrr",
	},
	"optional · totp, recordable, holding totp": {
		"oauth.authorize": "mmmmmmm",
		"oauth.consent": "mmmmmmm",
		"oauth.session_grant": "mmmmmmm",
		"oauth.code_exchange": "mmmmmmm",
		"oauth.refresh": "mmmmmmmm",
		"device.lookup": "mmmmmmm",
		"device.approve": "mmmmmmm",
		"device.deny": "mmmmmmm",
		"federation_grants.connect": "mmmmmmm",
		"federation_grants.consent": "mmmmmmm",
		"federation_grants.callback": "mmmmmmm",
		"session.link": "rsmsrrs",
		"session.link_callback": "mmmmmmm",
		"webauthn.register": "rsmsrrs",
		"mfa.manage": "rsmsrrs",
	},
	"required · totp, recordable, holding totp": {
		"oauth.authorize": "rsmmrrs",
		"oauth.consent": "rsmmrrs",
		"oauth.session_grant": "rsmmrrs",
		"oauth.code_exchange": "rsmmrrs",
		"oauth.refresh": "urrmmmrm",
		"device.lookup": "rmmmmmm",
		"device.approve": "rsmmrrs",
		"device.deny": "rmmmmmm",
		"federation_grants.connect": "rsmmrrs",
		"federation_grants.consent": "rsmmrrs",
		"federation_grants.callback": "rsmmrrs",
		"session.link": "rsmsrrs",
		"session.link_callback": "rsmmrrs",
		"webauthn.register": "rsmsrrs",
		"mfa.manage": "rsmsrrs",
	},
};
