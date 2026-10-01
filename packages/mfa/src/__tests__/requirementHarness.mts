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
 * What the `mfa` requirement's unit suites build it over: stand-in factors
 * by the values they declare (the TOTP factor's are the package's own), a
 * resolver over them as core's `mfaFactorResolver` answers, and a factor
 * record for a subject that holds one. Not a test file.
 */

import { randomBytes } from "node:crypto";
import {
	createMemoryMfaFactorStore,
	type MfaFactor,
	type MfaFactorRecord,
	type MfaFactorResolver,
	type MfaFactorStore,
} from "@o3co/auth-provider-core";
import { createMfaSealing } from "#/sealing.mjs";

/** The first-binding gate's inputs of a composition with no mail sender and no operator reset: no proof is asked, and none was given. */
export const WITHOUT_MAIL = {
	firstBinding: { requireEmailProof: "when-mail", mailWired: false },
	emailProofRequiredAtNextBinding: async () => false,
	sessionEmailProofAt: async () => null,
} as const;

/** A key ring's sealing of the suites' own: a record's data these suites hold as `"sealed"` does not open under it. */
export const SEALING = createMfaSealing({
	ring: [{ id: "requirement-suite", key: randomBytes(32) }],
});

/** A transaction store that holds no subject's first-binding mark. */
export const NO_FIRST_BINDING_MARK = {
	firstBindingAt: async () => null,
} as const;

/** What a login records of an account that is not enrolled and has no address: a session's enrollment facts. */
export const NOT_ENROLLED_FACTS = Object.freeze({
	witness: "not_enrolled",
	mailAddress: "none",
} as const);

/** A factor that declares `amrValues`, adds `mfa` or not, counts or not; it verifies nothing. */
export function stubFactor(
	kind: string,
	amrValues: readonly string[],
	options: { readonly addsMfa?: boolean; readonly counting?: boolean } = {},
): MfaFactor {
	return {
		kind,
		amrValues,
		amrFor: () => amrValues,
		addsMfa: options.addsMfa ?? true,
		counting: options.counting ?? true,
		guessable: false,
		describe: () => ({}),
		verify: async () => ({ ok: false, reason: "invalid" }),
		beginEnrollment: async () => ({ state: {}, response: {} }),
		completeEnrollment: async () => ({ ok: false, reason: "invalid" }),
	};
}

/** The factors a composition might install, by what each declares (the MFA ADR's D14). */
export const FACTORS: Readonly<
	Record<"totp" | "webauthn" | "email" | "recovery", () => MfaFactor>
> = {
	totp: () => stubFactor("totp", ["otp"]),
	webauthn: () => stubFactor("webauthn", ["hwk", "swk"]),
	email: () => stubFactor("email", ["email"], { addsMfa: false }),
	recovery: () => stubFactor("recovery_code", ["recovery"], { counting: false }),
};

/** A resolver over `factors`, as core's `mfaFactorResolver` answers: by kind, in the order given, read through at call time. */
export function resolverOver(factors: MfaFactor[]): MfaFactorResolver {
	return {
		get: (kind) => factors.find((factor) => factor.kind === kind),
		entries: function* () {
			for (const factor of factors) yield [factor.kind, factor] as const;
		},
	};
}

/** One factor record of `kind` for `subject`, as a store keeps it: its data opaque. */
export const factorRecord = (subject: string, kind = "totp", id = "f-1"): MfaFactorRecord => ({
	id,
	subject,
	kind,
	label: undefined,
	binding: "password",
	createdAt: new Date(0),
	lastUsedAt: undefined,
	version: 0,
	data: "sealed",
});

/** A factor store holding `records`, read by subject; its writes are a memory store's. */
export const factorStoreHolding = (...records: MfaFactorRecord[]): MfaFactorStore => ({
	...createMemoryMfaFactorStore(),
	list: async (subject) => records.filter((record) => record.subject === subject),
});

/** A factor store whose `list` cannot answer: an outage. */
export const unreachableFactorStore = (): MfaFactorStore => ({
	kind: "down",
	list: async () => {
		throw new Error("factor store unreachable");
	},
	create: async () => {
		throw new Error("factor store unreachable");
	},
	update: async () => {
		throw new Error("factor store unreachable");
	},
	remove: async () => {
		throw new Error("factor store unreachable");
	},
	removeAllForSubject: async () => {
		throw new Error("factor store unreachable");
	},
});
