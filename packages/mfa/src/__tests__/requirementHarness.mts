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

import {
	createMemoryMfaFactorStore,
	type MfaFactor,
	type MfaFactorRecord,
	type MfaFactorResolver,
	type MfaFactorStore,
} from "@o3co/auth-provider-core";

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
export const FACTORS = {
	totp: () => stubFactor("totp", ["otp"]),
	webauthn: () => stubFactor("webauthn", ["hwk", "swk"]),
	email: () => stubFactor("email", ["email"], { addsMfa: false }),
	recovery: () => stubFactor("recovery_code", ["recovery"], { counting: false }),
} as const;

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
