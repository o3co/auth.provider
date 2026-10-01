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
 * The conformance suite of a second factor — a value of core's `mfaFactors`
 * contribution kind.
 *
 * `mfaFactorContract(input)` holds a factor to what the coordinator relies on
 * whatever the kind: a kind a hint can carry; `amrValues` it can vouch for and
 * `amrFor` within them, never empty; boolean flags; state and data that
 * survive the JSON round trip sealing puts them through, which the suite also
 * hands the factor back after; a code asked to be mailed only for the call's
 * purpose, with an expiry after now when one is given, another at each
 * challenge, a login code with the keyed digest of the account's address, and
 * in no form in the page's response; the address digest it records exactly
 * the one it is handed — of the address its code went to, as the coordinator
 * kept it at the send — never one of the address the account answers at the
 * start or by the completion, and no completion without one; a digest a
 * verification is handed under a newer key kept in its next data and mailed
 * by the next challenge; over data
 * whose digest is gone or unreadable, a login code still asked for, with a
 * `null` digest, which the coordinator refuses; no answer — state,
 * response, data, label — carrying the account's address, as given or as
 * `normaliseMailAddress` spells it, which the provider keeps none of and a
 * page does not show; a hint that never shows it; a proof
 * the factor cannot read answered `malformed`, never thrown;
 * a valid proof that completes an enrollment and verifies the factor it
 * enrolled; and, for a factor that answers an identity, a non-empty string
 * for its enrolled data, the same at each reading, through a JSON round trip
 * and for a verification's next data, and over data it cannot read a
 * non-empty string or `undefined`, never one string for two such data
 * unless it is the enrolled data's own, never a throw. Given a second
 * authenticator's enrollment proof, the suite enrolls it through the same
 * factor beside the first one's record, and holds their data to two
 * different identities, neither `undefined`, each the same however and in
 * whatever order a factor reads it once both are enrolled: an identity too
 * coarse — a constant, or one two authenticators share — judges every second
 * enrollment of the kind a duplicate, and `undefined` is a duplicate of
 * none, never a distinct authenticator. Without that proof it enrolls one
 * authenticator alone and cannot tell. An identity is a duplicate key, not
 * an assurance signal: two identities do not show two devices, since one
 * authenticator can hold two credentials. The suite enrolls at one instant
 * and verifies an hour later, so a factor that
 * refuses reuse within a time step is not asked to verify at the
 * step it enrolled. Every call is made for the account's `User.id` as its
 * subject, and handed core's test digests (`createTestMfaDigests`), made for
 * the factor's kind. State and data are held to the rule the coordinator
 * seals them by: JSON values JSON gives back as they are, in plain or
 * null-prototype objects. A code and an address are looked for in the
 * strings an answer holds as a reader decodes them, not in its JSON text.
 */

import assert from "node:assert/strict";
import {
	FEDERATED_AMR,
	isHintToken,
	MFA_AMR,
	type MfaCeremonyContext,
	type MfaDigests,
	type MfaEnrolledFactor,
	type MfaFactor,
	type MfaFactorData,
	type MfaFactorMailPurpose,
	type MfaKeyedDigest,
	normaliseMailAddress,
	PASSWORD_AMR,
} from "@o3co/auth-provider-core";
import { type ContractCase, createTestMfaDigests } from "@o3co/auth-provider-core/testing";

/** What the start of an enrollment answers: the state the coordinator keeps, and the page's response. */
export type MfaFactorEnrollmentStart = Awaited<ReturnType<MfaFactor["beginEnrollment"]>>;

/** What a challenge answers: the state the coordinator keeps, if any, and the page's response. */
export type MfaFactorChallenge = Awaited<ReturnType<NonNullable<MfaFactor["challenge"]>>>;

export interface MfaFactorContractInput {
	/** A fresh factor for each case. */
	readonly build: () => MfaFactor;
	/** An account the factor can enroll, as the Store answers it (a `User`). */
	readonly user: Readonly<Record<string, unknown>>;
	/** The proof of possession that completes the enrollment `start` began, as a request carries it. */
	readonly enrollmentProof: (
		start: MfaFactorEnrollmentStart,
		context: MfaCeremonyContext,
	) => unknown;
	/**
	 * The proof of possession of an authenticator other than the one
	 * `enrollmentProof` proves, completing the enrollment `start` began. Given
	 * it, a factor with `identity` must answer the two enrolled data two
	 * different identities. Distinct identities name distinct records, not
	 * distinct devices.
	 */
	readonly secondEnrollmentProof?: (
		start: MfaFactorEnrollmentStart,
		context: MfaCeremonyContext,
	) => unknown;
	/**
	 * A proof that verifies `enrolled` at the context's time — after `challenge`,
	 * which the suite passes, when the factor has one.
	 */
	readonly verificationProof: (
		enrolled: MfaEnrolledFactor,
		challenge: MfaFactorChallenge | undefined,
		context: MfaCeremonyContext,
	) => unknown;
	/** Proofs the factor cannot read. Default: `undefined`, `null`, a number and an empty object. */
	readonly malformedProofs?: readonly unknown[];
}

/** The address the account's user record answers after the code went out, in the cases that change it. */
const MOVED_ADDRESS = "mfa-contract-moved@attacker.example";

/** An address neither the start nor the completion reads, whose digest the suite hands a completion. */
const HANDED_ADDRESS = "mfa-contract-sent-to@example.org";

/** What the suite puts where a factor's address digest was, to see it read as none. */
const UNREADABLE_DIGESTS: readonly unknown[] = [
	null,
	"digest",
	{},
	{ keyId: "test-key" },
	{ keyId: 1, digest: 2 },
	[],
];

/** What the suite puts in place of each member of a factor's data, to see an identity read it as none. */
const UNREADABLE_MEMBERS: readonly unknown[] = [null, 7, "x", [], {}];

/** When the suite enrolls, and an hour later, when it verifies. */
const ENROLLED_AT_MS = Date.UTC(2026, 0, 1);
const VERIFIED_AT_MS = ENROLLED_AT_MS + 3_600_000;
const FACTOR_ID = "contract-factor-1";
const SECOND_FACTOR_ID = "contract-factor-2";

const DEFAULT_MALFORMED: readonly unknown[] = [undefined, null, 1234, {}];

/**
 * Where `value` is not a JSON value JSON gives back as it is — the rule the
 * coordinator seals state and data by — as a path, or `undefined`: `null`,
 * booleans, finite numbers, strings, real arrays with no hole or `undefined`
 * entry, and objects whose prototype is `Object.prototype` or none, with no
 * accessor, whose `undefined` members JSON drops. Anything else — a Date, a
 * Map, a class instance, a function, BigInt, NaN, a cycle — is refused.
 */
function notJsonAt(
	value: unknown,
	path: string,
	ancestors: Set<object> = new Set(),
): string | undefined {
	if (value === null || typeof value === "string" || typeof value === "boolean") return undefined;
	if (typeof value === "number") return Number.isFinite(value) ? undefined : path;
	if (typeof value !== "object" || ancestors.has(value)) return path;
	const hasAccessor = Reflect.ownKeys(value).some((key) => {
		const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
		return descriptor !== undefined && !("value" in descriptor);
	});
	if (hasAccessor) return path;
	const prototype = Object.getPrototypeOf(value);
	ancestors.add(value);
	try {
		if (Array.isArray(value)) {
			if (prototype !== Array.prototype) return path;
			for (let index = 0; index < value.length; index++) {
				if (!Object.hasOwn(value, index) || value[index] === undefined) return `${path}[${index}]`;
				const found = notJsonAt(value[index], `${path}[${index}]`, ancestors);
				if (found !== undefined) return found;
			}
			return undefined;
		}
		if (prototype !== Object.prototype && prototype !== null) return path;
		for (const [key, member] of Object.entries(value)) {
			if (member === undefined) continue;
			const found = notJsonAt(member, `${path}.${key}`, ancestors);
			if (found !== undefined) return found;
		}
		return undefined;
	} finally {
		ancestors.delete(value);
	}
}

/** Refuses `value` unless JSON gives it back as it is, as the coordinator keeps it. */
function survivesJson(value: unknown, what: string): void {
	const at = notJsonAt(value, what);
	assert.ok(at === undefined, `${at} is not a value JSON gives back as it is`);
}

/** `value` as the coordinator hands it back after keeping it: through JSON. */
const reopened = <T,>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

/**
 * Every string `value` holds, as a reader of it decodes them: string, number
 * and bigint values, and the keys of objects, maps and arrays' holders,
 * through arrays, sets and maps, each object once.
 */
function decodedStrings(value: unknown, seen: Set<object> = new Set()): string[] {
	if (typeof value === "string") return [value];
	if (typeof value === "number" || typeof value === "bigint") return [String(value)];
	if (typeof value !== "object" || value === null || seen.has(value)) return [];
	seen.add(value);
	if (value instanceof Map) {
		return [...value].flatMap(([key, member]) => [
			...decodedStrings(key, seen),
			...decodedStrings(member, seen),
		]);
	}
	if (value instanceof Set) return [...value].flatMap((member) => decodedStrings(member, seen));
	return Object.entries(value).flatMap(([key, member]) => [key, ...decodedStrings(member, seen)]);
}

/** Text as the suite compares a code: lower case, letters and digits alone. */
const normalised = (text: string): string => text.toLowerCase().replace(/[^\p{L}\p{N}]/gu, "");

/** Whether `value` holds `code` in any string, compared normalised, or verbatim when nothing of it survives normalising. */
function carriesCode(value: unknown, code: string): boolean {
	const needle = normalised(code);
	return decodedStrings(value).some((text) =>
		needle === "" ? text.includes(code) : normalised(text).includes(needle),
	);
}

/**
 * Refuses a code a call asks to be mailed unless its purpose is `purpose`,
 * its code a non-empty string that `response`, what the page is answered,
 * carries in no form, and its expiry, when given, an instant after `nowMs`.
 * Answers the code; no mail asked for passes, answering nothing.
 */
function checkMail(
	mail: unknown,
	response: unknown,
	expected: {
		readonly purpose: MfaFactorMailPurpose;
		readonly nowMs: number;
		readonly what: string;
	},
): string | undefined {
	if (mail === undefined) return undefined;
	const { what } = expected;
	const { purpose, code, expiresAtMs } = (
		typeof mail === "object" && mail !== null ? mail : {}
	) as {
		readonly purpose?: unknown;
		readonly code?: unknown;
		readonly expiresAtMs?: unknown;
	};
	assert.equal(purpose, expected.purpose, `${what}'s mail is not for ${expected.purpose}`);
	assert.ok(typeof code === "string" && code.length > 0, `${what}'s mail has no code`);
	assert.ok(
		expiresAtMs === undefined ||
			(typeof expiresAtMs === "number" &&
				Number.isFinite(expiresAtMs) &&
				expiresAtMs > expected.nowMs),
		`${what}'s mail expires at ${String(expiresAtMs)}, not after now`,
	);
	assert.ok(
		!carriesCode(response, code),
		`${what}'s response carries the code it asks to be mailed: the page would hold what only the mailbox should`,
	);
	return code;
}

/** Whether `value` is a keyed digest: a key id and a digest, each a string. */
function isKeyedDigest(value: unknown): value is MfaKeyedDigest {
	if (typeof value !== "object" || value === null) return false;
	const { keyId, digest } = value as { readonly keyId?: unknown; readonly digest?: unknown };
	return typeof keyId === "string" && typeof digest === "string";
}

/**
 * Refuses a login code's `addressDigest` unless it is the keyed digest of the
 * account's address as `normaliseMailAddress` spells it, made for `kind`
 * under the digests a factor is handed.
 */
function checkAddressDigest(
	addressDigest: unknown,
	kind: string,
	user: Readonly<Record<string, unknown>>,
): void {
	const address = normaliseMailAddress(user.email);
	assert.ok(address !== undefined, "a factor mails a login code, and the account has no address");
	assert.ok(
		isKeyedDigest(addressDigest),
		"a login code carries no keyed digest of the address it goes to",
	);
	assert.equal(
		createTestMfaDigests(kind).matchesDigest([address], addressDigest),
		"match",
		"a login code carries the digest of another address than the account's",
	);
}

/**
 * `text` with every run of percent-escapes decoded as UTF-8, as a URI's
 * reader decodes it; a run that is no UTF-8 is kept as it is.
 */
const percentDecoded = (text: string): string =>
	text.replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => {
		try {
			return decodeURIComponent(run);
		} catch {
			return run;
		}
	});

/**
 * Refuses `value` when a string it holds carries the account's address,
 * whatever its case, as it is or percent-decoded: as the account gives it,
 * or as `normaliseMailAddress` spells it — trimmed, NFC, its domain in ASCII.
 */
function carriesNoAddress(value: unknown, user: Readonly<Record<string, unknown>>, what: string) {
	const { email } = user;
	if (typeof email !== "string" || email === "") return;
	const addresses = [email.toLowerCase(), normaliseMailAddress(email)].filter(
		(address): address is string => address !== undefined && address.trim() !== "",
	);
	assert.ok(
		!decodedStrings(value).some((text) =>
			[text, percentDecoded(text)].some((read) =>
				addresses.some((address) => read.toLowerCase().includes(address)),
			),
		),
		`${what} carries the account's address, which the provider does not keep and a page does not show`,
	);
}

/**
 * Refuses `value` when a string it holds, percent-decoded, carries the
 * account's address anywhere but in the account's username, verbatim: where
 * the username is the address, it may be named by it, and only so.
 */
function carriesNoAddressButUsername(
	value: unknown,
	user: Readonly<Record<string, unknown>>,
	what: string,
) {
	const { username, email } = user;
	const address = typeof email === "string" ? [email, normaliseMailAddress(email)] : [];
	// Only a username that holds the address is struck out: one that is part of it strikes nothing.
	const named =
		typeof username === "string" &&
		address.some(
			(spelling) =>
				spelling !== undefined &&
				spelling !== "" &&
				username.toLowerCase().includes(spelling.toLowerCase()),
		)
			? username
			: undefined;
	const rest = decodedStrings(value).map((text) => {
		const read = percentDecoded(text);
		return named === undefined ? read : read.split(named).join(" ");
	});
	carriesNoAddress(rest, user, what);
}

/** The account the error probes run over: a username and an address no factor's text holds by chance. */
const CANARY = {
	username: "mfa-contract-canary-q7x",
	email: "mfa-contract-canary-q7x@canary.example",
} as const;

/** What an error says: its name, message and own string properties, as a log line or its reader could show them. */
function errorText(error: unknown): string {
	try {
		if (typeof error !== "object" || error === null) return String(error);
		const own = Object.entries(error).filter(([, value]) => typeof value === "string");
		return [String(error), (error as { message?: unknown }).message, ...own.flat()].join("\n");
	} catch {
		return "";
	}
}

/**
 * Refuses `text` when it carries the account's address — as {@link carriesNoAddress}
 * reads it — or its username, whatever its case, as it is or percent-decoded.
 */
function carriesNoAccount(text: string, user: Readonly<Record<string, unknown>>, what: string) {
	carriesNoAddress(text, user, what);
	const { username } = user;
	if (typeof username !== "string" || username.trim() === "") return;
	const name = username.toLowerCase();
	assert.ok(
		![text, percentDecoded(text)].some((read) => read.toLowerCase().includes(name)),
		`${what} quotes the account's username, which a log line would carry`,
	);
}

/**
 * The keyed digest of `user`'s address as the coordinator makes it when it
 * mails a code there: `normaliseMailAddress`'s spelling, under `digests`.
 */
function digestOfAddress(
	digests: MfaDigests,
	user: Readonly<Record<string, unknown>>,
): MfaKeyedDigest | undefined {
	const address = normaliseMailAddress(user.email);
	return address === undefined ? undefined : digests.digest([address]);
}

/** Each copy of `data` with the member at `path` removed, or replaced by an unreadable digest. */
function damagedAt(data: MfaFactorData, path: readonly string[]): MfaFactorData[] {
	const [key, ...rest] = path as [string, ...string[]];
	if (rest.length > 0) {
		return damagedAt(data[key] as MfaFactorData, rest).map((inner) => ({ ...data, [key]: inner }));
	}
	const { [key]: _removed, ...without } = data;
	return [without, ...UNREADABLE_DIGESTS.map((value) => ({ ...data, [key]: value }))];
}

/** The path to the member of `value` equal to `digest`, through plain objects, or `undefined`. */
function pathTo(value: unknown, digest: MfaKeyedDigest): string[] | undefined {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
	for (const [key, member] of Object.entries(value)) {
		const { keyId, digest: made } = (member ?? {}) as { keyId?: unknown; digest?: unknown };
		if (keyId === digest.keyId && made === digest.digest) return [key];
		const inner = pathTo(member, digest);
		if (inner !== undefined) return [key, ...inner];
	}
	return undefined;
}

/** The subject every call is made for: the account's `User.id`, as the coordinator hands it. */
function subjectOf(user: Readonly<Record<string, unknown>>): string {
	const { id } = user;
	assert.ok(typeof id === "string" && id.length > 0, "the account has no id: a subject is User.id");
	return id;
}

/** Every call's context, for `subject`, at `nowMs`, under the transaction `transactionId`. */
const contextAt = (
	factor: MfaFactor,
	subject: string,
	nowMs: number,
	transactionId: string,
): MfaCeremonyContext => ({
	subject,
	transactionId,
	nowMs,
	request: { ip: "192.0.2.1", userAgent: "mfa-factor-contract" },
	digests: createTestMfaDigests(factor.kind),
});

/** The cases of the factor contract over the factors `input` builds. */
export function mfaFactorContract(input: MfaFactorContractInput): readonly ContractCase[] {
	const malformed = input.malformedProofs ?? DEFAULT_MALFORMED;

	/**
	 * The start of an enrollment beside the factors the subject `held`, and —
	 * when it asks for a code to be mailed — the digest of the address the code
	 * goes to, as the coordinator keeps it at the send.
	 */
	const begin = async (factor: MfaFactor, held: readonly MfaEnrolledFactor[] = []) => {
		const context = contextAt(factor, subjectOf(input.user), ENROLLED_AT_MS, "contract-enrollment");
		const start = await factor.beginEnrollment({ ...context, user: input.user, factors: held });
		const sentTo =
			start.mail === undefined ? undefined : digestOfAddress(context.digests, input.user);
		return { context, start, sentTo, held };
	};

	/** The completion of `begun` with `proof`, for `user` as the Store answers by then, as the coordinator hands it. */
	const complete = (
		factor: MfaFactor,
		begun: Awaited<ReturnType<typeof begin>>,
		proof: unknown,
		user: Readonly<Record<string, unknown>> = input.user,
	) =>
		factor.completeEnrollment({
			...begun.context,
			user,
			factors: begun.held,
			state: reopened(begun.start.state),
			proof,
			...(begun.sentTo === undefined ? {} : { addressDigest: begun.sentTo }),
		});

	/**
	 * The factor enrolled through its own ceremony with `proofOf`'s proof,
	 * beside the factor the subject holds when there is one, its data as the
	 * coordinator opens it.
	 */
	const enroll = async (
		factor: MfaFactor,
		proofOf: MfaFactorContractInput["enrollmentProof"] = input.enrollmentProof,
		held?: MfaEnrolledFactor,
	): Promise<MfaEnrolledFactor> => {
		const begun = await begin(factor, held === undefined ? [] : [held]);
		const done = await complete(factor, begun, await proofOf(begun.start, begun.context));
		assert.ok(
			done.ok,
			`the proof of possession did not complete the enrollment: ${JSON.stringify(done)}`,
		);
		return {
			id: held === undefined ? FACTOR_ID : SECOND_FACTOR_ID,
			label: done.label,
			createdAt: new Date(ENROLLED_AT_MS),
			lastUsedAt: undefined,
			data: reopened(done.data),
		};
	};

	/**
	 * A challenge of `enrolled`, when the factor has one, an hour after the
	 * enrollment. After a mailed login code the verification context carries
	 * the digest of the address it went to, as the coordinator keeps it at the
	 * send.
	 */
	const challenge = async (factor: MfaFactor, enrolled: MfaEnrolledFactor) => {
		const base = contextAt(factor, subjectOf(input.user), VERIFIED_AT_MS, "contract-verification");
		const sent =
			factor.challenge === undefined
				? undefined
				: await factor.challenge({ ...base, factor: enrolled, factors: [enrolled] });
		const sentTo = sent?.mail === undefined ? undefined : digestOfAddress(base.digests, input.user);
		const context = sentTo === undefined ? base : { ...base, addressDigest: sentTo };
		return { context, sent };
	};

	return [
		{
			name: "kind is a hint token: a lowercase letter, then up to 63 lowercase letters, digits, _ or -",
			run: async () => {
				const { kind } = input.build();
				assert.ok(isHintToken(kind), `kind ${JSON.stringify(kind)} is not one a hint can carry`);
			},
		},
		{
			name: "amrValues is a non-empty list of distinct non-empty strings, with no primary's marker and no mfa",
			run: async () => {
				const { amrValues } = input.build();
				assert.ok(Array.isArray(amrValues) && amrValues.length > 0, "amrValues is empty");
				assert.equal(new Set(amrValues).size, amrValues.length, "amrValues repeats a value");
				for (const value of amrValues) {
					assert.ok(
						typeof value === "string" && value.length > 0,
						"amrValues holds an empty value",
					);
					assert.ok(
						![PASSWORD_AMR, FEDERATED_AMR, MFA_AMR].includes(value),
						`amrValues holds ${value}: a second factor never adds a primary's marker, and mfa is addsMfa's`,
					);
				}
			},
		},
		{
			name: "addsMfa, counting and guessable are true or false, and reusableChallenge true, false or absent",
			run: async () => {
				const factor = input.build();
				for (const flag of ["addsMfa", "counting", "guessable"] as const) {
					assert.equal(typeof factor[flag], "boolean", `${flag} is not true or false`);
				}
				assert.ok(
					factor.reusableChallenge === undefined || typeof factor.reusableChallenge === "boolean",
					"reusableChallenge is neither true, false nor absent",
				);
			},
		},
		{
			name: "enrollable, when present, answers true for an account that can enroll the factor",
			run: async () => {
				const factor = input.build();
				if (factor.enrollable === undefined) return;
				assert.equal(factor.enrollable(input.user), true, "enrollable refuses the account");
			},
		},
		{
			name: "beginEnrollment answers state that survives a JSON round trip",
			run: async () => {
				const factor = input.build();
				const { start } = await begin(factor);
				survivesJson(start.state, "the pending enrollment's state");
			},
		},
		{
			name: "beginEnrollment, when it asks for a code to be mailed, asks for the enrollment code, non-empty, with an expiry after now when it gives one, and its response carries no form of the code",
			run: async () => {
				const factor = input.build();
				const { context, start } = await begin(factor);
				checkMail(start.mail, start.response, {
					purpose: "email_factor_enrollment",
					nowMs: context.nowMs,
					what: "beginEnrollment",
				});
			},
		},
		{
			name: "completeEnrollment answers malformed for a proof it cannot read, and never throws for one",
			run: async () => {
				const factor = input.build();
				const begun = await begin(factor);
				for (const proof of malformed) {
					const done = await complete(factor, begun, proof);
					assert.deepEqual(done, { ok: false, reason: "malformed" }, `the proof ${String(proof)}`);
				}
			},
		},
		{
			name: "completeEnrollment takes the proof of possession, and answers data that survives a JSON round trip, a label that is a string when present, and at least one amr value, each among amrValues",
			run: async () => {
				const factor = input.build();
				const begun = await begin(factor);
				const done = await complete(
					factor,
					begun,
					await input.enrollmentProof(begun.start, begun.context),
				);
				assert.ok(
					done.ok,
					`the proof of possession did not complete the enrollment: ${JSON.stringify(done)}`,
				);
				survivesJson(done.data, "the enrolled factor's data");
				assert.ok(
					done.label === undefined || typeof done.label === "string",
					"the label is not a string",
				);
				const amr = factor.amrFor(reopened(done.data));
				assert.ok(amr.length > 0, "amrFor answers no value: a verification would add nothing");
				for (const value of amr) {
					assert.ok(
						factor.amrValues.includes(value),
						`amrFor answers ${value}, which amrValues does not declare`,
					);
				}
			},
		},
		{
			name: "describe answers a hint that is a string, or none, and never the account's address",
			run: async () => {
				const factor = input.build();
				const { hint } = factor.describe((await enroll(factor)).data);
				assert.ok(hint === undefined || typeof hint === "string", "the hint is not a string");
				carriesNoAddress(
					hint,
					input.user,
					"the hint, which a page may show to whoever holds the password,",
				);
			},
		},
		{
			name: "challenge, when present, answers state that survives a JSON round trip",
			run: async () => {
				const factor = input.build();
				if (factor.challenge === undefined) return;
				const { sent } = await challenge(factor, await enroll(factor));
				if (sent?.state !== undefined) survivesJson(sent.state, "the challenge's state");
			},
		},
		{
			name: "challenge, when it asks for a code to be mailed, asks for a login code, non-empty, with an expiry after now when it gives one and the keyed digest of the account's address, another at each challenge, and its response carries no form of the code",
			run: async () => {
				const factor = input.build();
				if (factor.challenge === undefined) return;
				const enrolled = await enroll(factor);
				const codes: (string | undefined)[] = [];
				for (let n = 0; n < 2; n++) {
					const { context, sent } = await challenge(factor, enrolled);
					codes.push(
						checkMail(sent?.mail, sent?.response, {
							purpose: "login_code",
							nowMs: context.nowMs,
							what: "challenge",
						}),
					);
					if (sent?.mail !== undefined) {
						checkAddressDigest(
							(sent.mail as { readonly addressDigest?: unknown }).addressDigest,
							factor.kind,
							input.user,
						);
					}
				}
				if (codes[0] !== undefined) {
					assert.notEqual(codes[1], codes[0], "two challenges mail the same code");
				}
			},
		},
		{
			name: "completeEnrollment records exactly the address digest it is handed — of the address its code went to, kept at the send — never one of the address the account answered at the start or answers by the completion",
			run: async () => {
				const factor = input.build();
				const begun = await begin(factor);
				if (begun.sentTo === undefined) return;
				// The digest of an address neither the start nor the completion reads:
				// only what the factor is handed can put it in its data.
				const handed = digestOfAddress(begun.context.digests, {
					email: HANDED_ADDRESS,
				}) as MfaKeyedDigest;
				const moved = { ...input.user, email: MOVED_ADDRESS };
				const done = await complete(
					factor,
					{ ...begun, sentTo: handed },
					await input.enrollmentProof(begun.start, begun.context),
					moved,
				);
				assert.ok(
					done.ok,
					`the proof of possession did not complete the enrollment: ${JSON.stringify(done)}`,
				);
				assert.ok(
					pathTo(done.data, handed) !== undefined,
					"the enrolled data does not keep the address digest it was handed: the address its code went to",
				);
				const kept = decodedStrings(done.data);
				for (const [when, user] of [
					["the start", input.user],
					["the completion", moved],
				] as const) {
					const read = digestOfAddress(begun.context.digests, user)?.digest;
					assert.ok(
						read === undefined || !kept.includes(read),
						`the enrolled data keeps a digest of the address the account answered at ${when}, not the one it was handed`,
					);
				}
			},
		},
		{
			name: "completeEnrollment, after its code was mailed, completes nothing when it is handed no address digest",
			run: async () => {
				const factor = input.build();
				const begun = await begin(factor);
				if (begun.sentTo === undefined) return;
				const done = await complete(
					factor,
					{ ...begun, sentTo: undefined },
					await input.enrollmentProof(begun.start, begun.context),
				);
				assert.ok(
					!done.ok,
					"a completion after a mailed code, handed no address digest, completed: what it recorded is no address a code went to",
				);
			},
		},
		{
			name: "verify, handed the address digest under a newer key than the one recorded, keeps it in its next data, and a later challenge mails it",
			run: async () => {
				const factor = input.build();
				if (factor.challenge === undefined) return;
				const enrolled = await enroll(factor);
				const { context, sent } = await challenge(factor, enrolled);
				if (sent?.mail === undefined) return;
				// The ring's first key has changed since the enrollment: the digest kept at
				// the send is under the newer one.
				const rotated = createTestMfaDigests(factor.kind, { rotated: true });
				const handed = digestOfAddress(rotated, input.user) as MfaKeyedDigest;
				const verdict = await factor.verify({
					...context,
					digests: rotated,
					addressDigest: handed,
					factor: enrolled,
					factors: [enrolled],
					state: sent.state === undefined ? undefined : reopened(sent.state),
					proof: await input.verificationProof(enrolled, sent, context),
				});
				assert.ok(verdict.ok, `a valid proof was refused: ${JSON.stringify(verdict)}`);
				assert.ok(
					verdict.next !== undefined && pathTo(verdict.next, handed) !== undefined,
					"the factor's next data does not keep the address digest it was handed under the newer key: the older key could never leave the ring",
				);
				const rewrapped: MfaEnrolledFactor = { ...enrolled, data: reopened(verdict.next) };
				const later = await factor.challenge({
					...contextAt(factor, subjectOf(input.user), VERIFIED_AT_MS + 60_000, "contract-later"),
					digests: rotated,
					factor: rewrapped,
					factors: [rewrapped],
				});
				const mailed = (later.mail as { readonly addressDigest?: unknown } | undefined)
					?.addressDigest;
				assert.ok(
					isKeyedDigest(mailed) && mailed.keyId === handed.keyId && mailed.digest === handed.digest,
					"a later challenge does not mail the address digest kept under the newer key",
				);
			},
		},
		{
			name: "challenge, over data whose address digest is gone or is no digest, still asks for its login code, with a null address digest, and never throws: the coordinator refuses the factor",
			run: async () => {
				const factor = input.build();
				if (factor.challenge === undefined) return;
				const enrolled = await enroll(factor);
				const { sent: intact } = await challenge(factor, enrolled);
				const recorded = (intact?.mail as { readonly addressDigest?: unknown } | undefined)
					?.addressDigest;
				// Where the data keeps the digest the login code carries; a code that carries
				// none, or none the data holds as it is, is the mailed-code case's to refuse.
				const path = isKeyedDigest(recorded) ? pathTo(enrolled.data, recorded) : undefined;
				if (path === undefined) return;
				for (const data of damagedAt(enrolled.data, path)) {
					const damaged: MfaEnrolledFactor = { ...enrolled, data };
					const what = `over data ${JSON.stringify(data)}`;
					let sent: Awaited<ReturnType<typeof challenge>>["sent"];
					try {
						({ sent } = await challenge(factor, damaged));
					} catch (error) {
						assert.fail(
							`challenge threw ${what} (${String(error)}): an unreadable address digest is a mismatch the coordinator refuses, never an outage`,
						);
					}
					const mail = sent?.mail as { readonly addressDigest?: unknown } | undefined;
					assert.ok(
						typeof mail === "object" && mail !== null,
						`challenge ${what} asks for no login code: the coordinator cannot refuse the factor`,
					);
					if (mail.addressDigest === null) continue;
					checkAddressDigest(mail.addressDigest, factor.kind, input.user);
				}
			},
		},
		{
			name: "nothing kept, and no challenge's answer, carries the account's address — an enrollment's answer only as the account's username, verbatim — whatever its case or escaping: the pending enrollment's state and answer, the enrolled data and label, a challenge's state and answer, and a verification's next data",
			run: async () => {
				const factor = input.build();
				const begun = await begin(factor);
				carriesNoAddress(begun.start.state, input.user, "the pending enrollment's state");
				// An enrollment's answer goes to the account's own browser: it may name the account by its username.
				carriesNoAddressButUsername(
					begun.start.response,
					input.user,
					"the pending enrollment's answer",
				);
				const done = await complete(
					factor,
					begun,
					await input.enrollmentProof(begun.start, begun.context),
				);
				assert.ok(
					done.ok,
					`the proof of possession did not complete the enrollment: ${JSON.stringify(done)}`,
				);
				carriesNoAddress(done.data, input.user, "the enrolled factor's data");
				carriesNoAddress(done.label, input.user, "the enrolled factor's label");
				const enrolled: MfaEnrolledFactor = {
					id: FACTOR_ID,
					label: done.label,
					createdAt: new Date(ENROLLED_AT_MS),
					lastUsedAt: undefined,
					data: reopened(done.data),
				};
				const { context: later, sent } = await challenge(factor, enrolled);
				carriesNoAddress(sent?.state, input.user, "the challenge's state");
				// A login's challenge answers whoever holds the password.
				carriesNoAddress(sent?.response, input.user, "the challenge's answer");
				const verdict = await factor.verify({
					...later,
					factor: enrolled,
					factors: [enrolled],
					state: sent?.state === undefined ? undefined : reopened(sent.state),
					proof: await input.verificationProof(enrolled, sent, later),
				});
				if (verdict.ok) carriesNoAddress(verdict.next, input.user, "the factor's next data");
			},
		},
		{
			name: "an error the factor throws — over an account without a username, or a pending state or data it cannot read — quotes neither the account's address nor its username",
			run: async () => {
				const factor = input.build();
				const enrolled = await enroll(factor);
				const begun = await begin(factor);
				const unreadable = { ...enrolled, data: {} };
				// The suite's canary accounts, so a username that is an ordinary word is never
				// mistaken: one named apart from its address, one named by it.
				for (const account of [
					{ ...input.user, ...CANARY },
					{ ...input.user, username: CANARY.email, email: CANARY.email },
				]) {
					const { username: _username, ...nameless } = account;
					const attempts: [string, () => Promise<unknown>][] = [
						[
							"beginEnrollment over an account without a username",
							() => factor.beginEnrollment({ ...begun.context, user: nameless, factors: [] }),
						],
						[
							"completeEnrollment over a pending state it cannot read",
							() =>
								factor.completeEnrollment({
									...begun.context,
									user: account,
									factors: [],
									state: {},
									proof: "000000",
								}),
						],
						[
							"challenge over data it cannot read",
							async () =>
								factor.challenge?.({
									...contextAt(
										factor,
										subjectOf(input.user),
										VERIFIED_AT_MS,
										"contract-verification",
									),
									factor: unreadable,
									factors: [unreadable],
								}),
						],
						[
							"verify over data it cannot read",
							() =>
								factor.verify({
									...contextAt(
										factor,
										subjectOf(input.user),
										VERIFIED_AT_MS,
										"contract-verification",
									),
									factor: unreadable,
									factors: [unreadable],
									state: undefined,
									proof: "000000",
								}),
						],
					];
					for (const [what, attempt] of attempts) {
						let thrown: unknown;
						try {
							await attempt();
							continue;
						} catch (error) {
							thrown = error;
						}
						carriesNoAccount(errorText(thrown), account, `the error ${what} threw`);
					}
				}
			},
		},
		{
			name: "verify answers malformed for a proof it cannot read, and never throws for one",
			run: async () => {
				const factor = input.build();
				const enrolled = await enroll(factor);
				for (const proof of malformed) {
					const { context, sent } = await challenge(factor, enrolled);
					const verdict = await factor.verify({
						...context,
						factor: enrolled,
						factors: [enrolled],
						state: sent?.state === undefined ? undefined : reopened(sent.state),
						proof,
					});
					assert.deepEqual(
						verdict,
						{ ok: false, reason: "malformed" },
						`the proof ${String(proof)}`,
					);
				}
			},
		},
		{
			name: "verify takes a valid proof, names a factor the subject holds, and answers next data that survives a JSON round trip",
			run: async () => {
				const factor = input.build();
				const enrolled = await enroll(factor);
				const { context, sent } = await challenge(factor, enrolled);
				const verdict = await factor.verify({
					...context,
					factor: enrolled,
					factors: [enrolled],
					state: sent?.state === undefined ? undefined : reopened(sent.state),
					proof: await input.verificationProof(enrolled, sent, context),
				});
				assert.ok(verdict.ok, `a valid proof was refused: ${JSON.stringify(verdict)}`);
				assert.equal(
					verdict.factorId,
					enrolled.id,
					"the verification names a factor the subject does not hold",
				);
				if (verdict.next !== undefined) survivesJson(verdict.next, "the factor's next data");
			},
		},
		{
			name: "identity, when present, answers the enrolled data a non-empty string, the same at a second reading, through another JSON round trip, and for the next data a verification answers",
			run: async () => {
				const factor = input.build();
				if (factor.identity === undefined) return;
				const enrolled = await enroll(factor);
				const identity = factor.identity(enrolled.data);
				assert.ok(
					typeof identity === "string" && identity.length > 0,
					"identity answers no string for the data its enrollment completed with: no duplicate of it could be found",
				);
				assert.equal(
					factor.identity(enrolled.data),
					identity,
					"identity answers another string at a second reading of the same data",
				);
				assert.equal(
					factor.identity(reopened(enrolled.data)),
					identity,
					"identity answers another string for the same data after another JSON round trip",
				);
				const { context, sent } = await challenge(factor, enrolled);
				const verdict = await factor.verify({
					...context,
					factor: enrolled,
					factors: [enrolled],
					state: sent?.state === undefined ? undefined : reopened(sent.state),
					proof: await input.verificationProof(enrolled, sent, context),
				});
				assert.ok(verdict.ok, `a valid proof was refused: ${JSON.stringify(verdict)}`);
				if (verdict.next === undefined) return;
				assert.equal(
					factor.identity(reopened(verdict.next)),
					identity,
					"a verification's next data answers another identity: using an authenticator does not change which it is",
				);
			},
		},
		{
			name: "identity, when present, answers a non-empty string or undefined over data it cannot read, never one string for two of them unless it is the enrolled data's own, and never throws",
			run: async () => {
				const factor = input.build();
				const { identity } = factor;
				if (identity === undefined) return;
				const { data } = await enroll(factor);
				const own = identity.call(factor, data);
				const damagedData: MfaFactorData[] = [
					{},
					{ unexpected: true },
					...Object.keys(data).flatMap((key) => {
						const { [key]: _removed, ...without } = data;
						return [without, ...UNREADABLE_MEMBERS.map((value) => ({ ...data, [key]: value }))];
					}),
				];
				// Each once: data with its one member removed is `{}` again.
				const unreadable = [
					...new Map(damagedData.map((damaged) => [JSON.stringify(damaged), damaged])).values(),
				];
				/** Which damaged data answered each string other than the enrolled data's own. */
				const answeredBy = new Map<string, string>();
				for (const damaged of unreadable) {
					const what = `over data ${JSON.stringify(damaged)}`;
					let answered: unknown;
					try {
						answered = identity.call(factor, damaged);
					} catch (error) {
						assert.fail(
							`identity threw ${what} (${String(error)}): the coordinator reads a throw as no identity, so the record is judged a duplicate of none`,
						);
					}
					assert.ok(
						answered === undefined || (typeof answered === "string" && answered.length > 0),
						`identity ${what} answers ${JSON.stringify(answered)}, neither a non-empty string nor undefined`,
					);
					if (answered === undefined || answered === own) continue;
					const earlier = answeredBy.get(answered);
					assert.ok(
						earlier === undefined,
						`identity answers ${JSON.stringify(answered)} both ${earlier} and ${what}: records it cannot read would be judged one authenticator`,
					);
					answeredBy.set(answered, what);
				}
			},
		},
		{
			name: "identity, when present and given a second authenticator's enrollment proof, answers the enrolled data of the two authenticators two different non-empty strings, each the same once both are enrolled through the factor that enrolled it or a fresh one, in either order: an absent identity is a duplicate of none, never a distinct authenticator",
			run: async () => {
				const factor = input.build();
				const { secondEnrollmentProof } = input;
				if (factor.identity === undefined || secondEnrollmentProof === undefined) return;
				// As the coordinator enrolls a second authenticator, beside the record it holds.
				const held = await enroll(factor);
				const first = factor.identity(reopened(held.data));
				const added = await enroll(factor, secondEnrollmentProof, held);
				const second = factor.identity(reopened(added.data));
				for (const identity of [first, second]) {
					assert.ok(
						typeof identity === "string" && identity.length > 0,
						`identity answers ${JSON.stringify(identity)} for an authenticator's enrolled data: an absent identity is a duplicate of none, so it cannot count as a distinct authenticator`,
					);
				}
				assert.notEqual(
					first,
					second,
					"identity answers two authenticators' enrolled data one string: every second enrollment would be judged a duplicate",
				);
				// An identity is its data's alone: no later enrollment, object, factor
				// instance or reading order changes it. A fresh factor reads the second first.
				const fresh = input.build();
				const readings: readonly [MfaFactor, MfaEnrolledFactor, string | undefined][] = [
					[factor, held, first],
					[factor, added, second],
					[fresh, added, second],
					[fresh, held, first],
				];
				for (const [reader, record, identity] of readings) {
					assert.equal(
						reader.identity?.(reopened(record.data)),
						identity,
						"identity answers a record another string once another is enrolled, through another factor, or read in another order: duplicates would be judged by what the factor last did, not by the record",
					);
				}
			},
		},
	];
}
