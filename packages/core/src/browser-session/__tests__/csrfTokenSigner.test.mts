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
 * The `csrfTokenSigner` slot: the CSRF token's signing key has one
 * owner — the session store's module, which owns `session.secret` — and it
 * reaches the session module's `csrfGuard` provider as this narrow signer, the
 * key derived and kept inside it. Its contract suite and the test double: the
 * double keeps every case, and each way a signer can break the contract fails
 * the case that names it.
 */

import { createHmac, randomBytes } from "node:crypto";
import { describe, expect, expectTypeOf, it } from "vitest";
import type { CsrfTokenSigner } from "#/browser-session/types.mjs";
import { createApp, defineModule, type ProviderDeps } from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import {
	type CsrfTokenSignerContractInput,
	createTestCsrfTokenSigner,
	csrfTokenSignerContract,
} from "#/testing/index.mjs";

const RULES = {
	shape: "sign answers a non-empty base64url signature, the same one for the same payload",
	roundTrip: "verify accepts the signature sign answered for the payload",
	changedSignature: "verify refuses a changed, shortened or lengthened signature",
	changedPayload: "verify refuses a signature for another payload",
	otherSigner: "verify refuses another signer's signature, and the two sign differently",
	malformed:
		"verify never throws: an empty, non-base64url or wrong-length signature, or a value that is not a string, is refused",
	alone:
		"the signer is a plain object carrying sign and verify alone, own or inherited: no key and no secret",
	frozen: "the signer is frozen",
	separated:
		"the signature is not the session cookie's: not an HMAC of the payload under the session secret itself",
} as const;

const SESSION_SECRET = "contract-session-secret.at-least-32-bytes.ok";

/** The names of the cases the signers `input` builds fail. */
const failing = async (input: CsrfTokenSignerContractInput): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of csrfTokenSignerContract(input)) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

/** A signer over `sign` and `verify`, frozen as a provider hands it. */
const signerOf = (
	sign: (payload: string) => string,
	verify: (payload: string, signature: string) => boolean,
): CsrfTokenSigner => Object.freeze({ sign, verify });

/** The double with `members` put over it. */
const doubleWith =
	(members: (original: CsrfTokenSigner) => Partial<CsrfTokenSigner>) => (): CsrfTokenSigner => {
		const original = createTestCsrfTokenSigner();
		return Object.freeze({ ...original, ...members(original) });
	};

const hmac = (key: string | Buffer, payload: string, encoding: "base64url" | "base64" | "hex") =>
	createHmac("sha256", key).update(payload, "utf8").digest(encoding);

describe("the csrfTokenSigner slot", () => {
	it("is optional, and holds sign and verify", () => {
		expectTypeOf<ComponentMap["csrfTokenSigner"]>().toEqualTypeOf<CsrfTokenSigner | undefined>();
		expectTypeOf<
			ProviderDeps<"csrfTokenSigner">["csrfTokenSigner"]
		>().toEqualTypeOf<CsrfTokenSigner>();
		expectTypeOf<CsrfTokenSigner["sign"]>().toEqualTypeOf<(payload: string) => string>();
		expectTypeOf<CsrfTokenSigner["verify"]>().toEqualTypeOf<
			(payload: string, signature: string) => boolean
		>();
		expect(true).toBe(true);
	});

	it("is filled by a module, and read by another", async () => {
		const signer = createTestCsrfTokenSigner();
		let seen: CsrfTokenSigner | undefined;
		const owner = defineModule({
			name: "test-csrf-token-signer-owner",
			provides: { csrfTokenSigner: () => signer },
		});
		const reader = defineModule({
			name: "test-csrf-token-signer-reader",
			requires: ["csrfTokenSigner"] as const,
			contributes: {
				grantMiddleware: [
					(deps) => {
						seen = deps.csrfTokenSigner;
						return null;
					},
				],
			},
		});
		const handle = await createApp({
			modules: [owner, reader],
			bootstrapComponents: {
				config: makeValidCoreConfig(),
				pathResolver: (p: string) => p,
			} as never,
		});
		try {
			expect(seen).toBe(signer);
		} finally {
			await handle.dispose();
		}
	});
});

describe("csrfTokenSignerContract — the double", () => {
	const input: CsrfTokenSignerContractInput = {
		build: () => createTestCsrfTokenSigner(),
		other: () => createTestCsrfTokenSigner(),
		sessionSecret: SESSION_SECRET,
	};

	it("names every rule", () => {
		expect(csrfTokenSignerContract(input).map((c) => c.name)).toEqual([
			RULES.shape,
			RULES.roundTrip,
			RULES.changedSignature,
			RULES.changedPayload,
			RULES.otherSigner,
			RULES.malformed,
			RULES.alone,
			RULES.frozen,
			RULES.separated,
		]);
	});

	it("leaves out the separation case for a signer whose session secret the suite is not given", () => {
		const names = csrfTokenSignerContract({
			build: input.build,
			other: input.other,
		}).map((c) => c.name);
		expect(names).not.toContain(RULES.separated);
	});

	it.each(csrfTokenSignerContract(input))("$name", async ({ run }) => {
		await run();
	});
});

describe("createTestCsrfTokenSigner", () => {
	it("draws a key of its own: two doubles sign one payload differently", () => {
		expect(createTestCsrfTokenSigner().sign("payload")).not.toBe(
			createTestCsrfTokenSigner().sign("payload"),
		);
	});
});

describe("csrfTokenSignerContract — each way a signer can break it", () => {
	const other = () => createTestCsrfTokenSigner();

	it("a signature drawn afresh each time", async () => {
		const build = doubleWith((original) => ({
			sign: (payload) => original.sign(`${payload}.${randomBytes(4).toString("hex")}`),
		}));
		expect(await failing({ build, other })).toContain(RULES.shape);
	});

	it("a signature that is base64 rather than base64url", async () => {
		const key = randomBytes(32);
		const build = () =>
			signerOf(
				(payload) => hmac(key, payload, "base64"),
				(payload, signature) =>
					typeof payload === "string" && signature === hmac(key, payload, "base64"),
			);
		expect(await failing({ build, other })).toEqual([RULES.shape]);
	});

	it("a signer that signs every payload alike", async () => {
		// A signature of one letter repeated: changing a character must change it to another.
		const alike = "A".repeat(43);
		const build = () =>
			signerOf(
				() => alike,
				(payload, signature) => typeof payload === "string" && signature === alike,
			);
		expect(await failing({ build, other })).toEqual([RULES.changedPayload]);
	});

	it("a verify that accepts anything", async () => {
		const build = doubleWith(() => ({ verify: () => true }));
		expect(await failing({ build, other })).toEqual([
			RULES.changedSignature,
			RULES.changedPayload,
			RULES.otherSigner,
			RULES.malformed,
		]);
	});

	it("a verify that refuses everything", async () => {
		const build = doubleWith(() => ({ verify: () => false }));
		expect(await failing({ build, other })).toEqual([RULES.roundTrip]);
	});

	it("a verify that compares only the start of the signature", async () => {
		const build = doubleWith((original) => ({
			verify: (payload, signature) =>
				typeof signature === "string" &&
				signature.length > 0 &&
				original.sign(payload).startsWith(signature.slice(0, 8)),
		}));
		expect(await failing({ build, other })).toContain(RULES.changedSignature);
	});

	it("a verify that ignores the payload", async () => {
		const build = doubleWith((original) => {
			const issued = new Set<string>();
			return {
				sign: (payload) => {
					const signature = original.sign(payload);
					issued.add(signature);
					return signature;
				},
				verify: (_payload, signature) => issued.has(signature),
			};
		});
		// A payload that is not a string, beside a signature it issued, is accepted too.
		expect(await failing({ build, other })).toEqual([RULES.changedPayload, RULES.malformed]);
	});

	it("a signer whose key does not depend on what it was built from", async () => {
		const key = randomBytes(32);
		const fixed = () =>
			signerOf(
				(payload) => hmac(key, payload, "base64url"),
				(payload, signature) =>
					typeof payload === "string" && signature === hmac(key, payload, "base64url"),
			);
		expect(await failing({ build: fixed, other: fixed })).toEqual([RULES.otherSigner]);
	});

	it("a verify that throws on a malformed signature", async () => {
		const build = doubleWith((original) => ({
			verify: (payload, signature) => {
				if (!/^[A-Za-z0-9_-]+$/.test(signature)) throw new TypeError("not base64url");
				return original.verify(payload, signature);
			},
		}));
		expect(await failing({ build, other })).toEqual([RULES.malformed]);
	});

	it("a verify that coerces what it is given to a string", async () => {
		const build = doubleWith((original) => ({
			verify: (payload, signature) => original.verify(String(payload), String(signature)),
		}));
		// An object whose toString answers the signature is accepted.
		expect(await failing({ build, other })).toEqual([RULES.malformed]);
	});

	it("a signer that carries its key", async () => {
		const build = () => {
			const key = randomBytes(32).toString("hex");
			return Object.freeze({
				key,
				sign: (payload: string) => hmac(key, payload, "base64url"),
				verify: (payload: string, signature: string) =>
					typeof payload === "string" && signature === hmac(key, payload, "base64url"),
			}) as CsrfTokenSigner;
		};
		expect(await failing({ build, other })).toEqual([RULES.alone]);
	});

	it("a frozen signer whose own prototype carries its key", async () => {
		const build = () => {
			const key = randomBytes(32).toString("hex");
			const signer = Object.create({ key }) as CsrfTokenSigner;
			return Object.freeze(
				Object.assign(signer, {
					sign: (payload: string) => hmac(key, payload, "base64url"),
					verify: (payload: string, signature: string) =>
						typeof payload === "string" && signature === hmac(key, payload, "base64url"),
				}),
			);
		};
		expect(await failing({ build, other })).toEqual([RULES.alone]);
	});

	it("a signer whose prototype is neither Object.prototype nor null, though it carries nothing", async () => {
		const build = () =>
			Object.freeze(
				Object.assign(Object.create(Object.freeze({})) as CsrfTokenSigner, {
					...createTestCsrfTokenSigner(),
				}),
			);
		expect(await failing({ build, other })).toEqual([RULES.alone]);
	});

	it("a signer with sign and verify on its class's prototype", async () => {
		class ClassSigner implements CsrfTokenSigner {
			readonly #inner = createTestCsrfTokenSigner();
			sign(payload: string): string {
				return this.#inner.sign(payload);
			}
			verify(payload: string, signature: string): boolean {
				return this.#inner.verify(payload, signature);
			}
		}
		const build = () => Object.freeze(new ClassSigner());
		expect(await failing({ build, other })).toEqual([RULES.alone]);
	});

	it("keeps a signer with a null prototype", async () => {
		const build = () =>
			Object.freeze(
				Object.assign(Object.create(null) as CsrfTokenSigner, { ...createTestCsrfTokenSigner() }),
			);
		expect(await failing({ build, other })).toEqual([]);
	});

	it("a signer that is not frozen", async () => {
		const build = () => ({ ...createTestCsrfTokenSigner() });
		expect(await failing({ build, other })).toEqual([RULES.frozen]);
	});

	it("a signer keyed by the session secret itself, as the session cookie is", async () => {
		const build = () =>
			signerOf(
				(payload) => hmac(SESSION_SECRET, payload, "base64url"),
				(payload, signature) =>
					typeof payload === "string" && signature === hmac(SESSION_SECRET, payload, "base64url"),
			);
		const another = () =>
			signerOf(
				(payload) => hmac("another-secret", payload, "base64url"),
				(payload, signature) =>
					typeof payload === "string" && signature === hmac("another-secret", payload, "base64url"),
			);
		expect(await failing({ build, other: another, sessionSecret: SESSION_SECRET })).toEqual([
			RULES.separated,
		]);
	});
});
