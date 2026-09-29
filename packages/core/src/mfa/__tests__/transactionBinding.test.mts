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
 * What an MFA transaction is bound to: a typed binding, not a bare
 * browser session id. `isMfaTransactionBoundTo` is the one comparison every
 * use of a transaction makes, and it compares the whole binding, kind
 * included; the contract suite holds each store to keeping the binding whole.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import * as core from "#/index.mjs";
import {
	isMfaTransactionBoundTo,
	type MfaTransaction,
	type MfaTransactionBinding,
	newMfaTransactionRecord,
} from "#/mfa/transactionStore.mjs";

const bound = (binding: unknown): Pick<MfaTransaction, "binding"> =>
	({ binding }) as Pick<MfaTransaction, "binding">;

describe("MfaTransactionBinding", () => {
	it("is a union discriminated by kind, a browser session its one member today", () => {
		expectTypeOf<MfaTransactionBinding["kind"]>().toEqualTypeOf<"session">();
		expectTypeOf<Extract<MfaTransactionBinding, { kind: "session" }>>().toEqualTypeOf<{
			readonly kind: "session";
			readonly id: string;
		}>();
		expectTypeOf<MfaTransaction["binding"]>().toEqualTypeOf<MfaTransactionBinding>();
		expectTypeOf<MfaTransaction>().not.toHaveProperty("sessionId");
	});

	it("and its comparison and bound read are on the package's root", () => {
		expect(core.isMfaTransactionBoundTo).toBe(isMfaTransactionBoundTo);
		expect(typeof core.getBoundMfaTransaction).toBe("function");
	});
});

describe("isMfaTransactionBoundTo", () => {
	const session: MfaTransactionBinding = { kind: "session", id: "express-session-1" };

	it("holds for the same binding", () => {
		expect(
			isMfaTransactionBoundTo(bound(session), { kind: "session", id: "express-session-1" }),
		).toBe(true);
	});

	it.each<[string, unknown]>([
		["another id", { kind: "session", id: "express-session-2" }],
		["another kind, the same id", { kind: "client", id: "express-session-1" }],
		["the id and more", { kind: "session", id: "express-session-1x" }],
		["a prefix of the id", { kind: "session", id: "express-session-" }],
		["an empty id", { kind: "session", id: "" }],
		["the id alone, as a bare session id", "express-session-1"],
		["the id without a kind", { id: "express-session-1" }],
		["the kind without an id", { kind: "session" }],
		["null", null],
		["nothing", undefined],
	])("does not hold for %s", (_label, other) => {
		expect(isMfaTransactionBoundTo(bound(session), other as MfaTransactionBinding)).toBe(false);
	});

	it.each<[string, unknown]>([
		["a bare session id", "express-session-1"],
		["no binding", undefined],
		["a binding of a kind it does not know", { kind: "client", id: "express-session-1" }],
		["a binding whose id is empty", { kind: "session", id: "" }],
	])("does not hold for a transaction with %s, whatever it is compared with", (_label, binding) => {
		expect(isMfaTransactionBoundTo(bound(binding), session)).toBe(false);
		expect(isMfaTransactionBoundTo(bound(binding), binding as MfaTransactionBinding)).toBe(false);
	});

	it("does not hold for something that is not a transaction", () => {
		for (const tx of [null, undefined, "express-session-1"]) {
			expect(isMfaTransactionBoundTo(tx as never, session)).toBe(false);
		}
	});

	it.each([
		["two different lone surrogates", "s\uD800", "s\uDC00"],
		["a lone surrogate and the replacement character", "s\uDBFF", "s\uFFFD"],
		["one lone surrogate and itself", "s\uD800", "s\uD800"],
	])("does not hold for an id that is not well formed: %s", (_label, held, presented) => {
		// Each lone surrogate encodes as U+FFFD's bytes: compared as bytes, two
		// different ids would be one.
		expect(
			isMfaTransactionBoundTo(bound({ kind: "session", id: held }), {
				kind: "session",
				id: presented,
			}),
		).toBe(false);
		expect(
			isMfaTransactionBoundTo(bound({ kind: "session", id: presented }), {
				kind: "session",
				id: held,
			}),
		).toBe(false);
	});

	it("holds for an id with a well-formed surrogate pair", () => {
		const pair: MfaTransactionBinding = { kind: "session", id: "s\uD83D\uDE00" };
		expect(isMfaTransactionBoundTo(bound(pair), { kind: "session", id: "s😀" })).toBe(true);
	});

	it("reads a presented binding's kind and id once, and answers false where reading one throws", () => {
		let reads = 0;
		const shifting = {
			kind: "session",
			get id() {
				reads += 1;
				return reads === 1 ? "express-session-1" : "express-session-2";
			},
		};
		expect(isMfaTransactionBoundTo(bound(session), shifting as MfaTransactionBinding)).toBe(true);
		expect(reads).toBe(1);
		for (const throwing of THROWING) {
			expect(isMfaTransactionBoundTo(bound(session), throwing as MfaTransactionBinding)).toBe(
				false,
			);
			expect(isMfaTransactionBoundTo(bound(throwing), session)).toBe(false);
		}
		expect(isMfaTransactionBoundTo(THROWING_HOLDER as never, session)).toBe(false);
	});
});

/** Bindings whose every read of `kind` or `id` — or the object itself — throws. */
const THROWING: readonly unknown[] = [
	{
		kind: "session",
		get id(): string {
			throw new Error("the id's getter throws");
		},
	},
	{
		get kind(): string {
			throw new Error("the kind's getter throws");
		},
		id: "express-session-1",
	},
	new Proxy(
		{},
		{
			get() {
				throw new Error("the proxy's get trap throws");
			},
		},
	),
	(() => {
		const { proxy, revoke } = Proxy.revocable({ kind: "session", id: "express-session-1" }, {});
		revoke();
		return proxy;
	})(),
];

/** A transaction whose `binding` getter throws. */
const THROWING_HOLDER = {
	get binding(): never {
		throw new Error("the transaction's binding getter throws");
	},
};

/** A step-up transaction every record rule admits, for `newMfaTransactionRecord`. */
const TX = (binding: unknown): MfaTransaction =>
	({
		id: "tx-1",
		purpose: "step_up",
		binding,
		subject: "user-1",
		sid: "sid-1",
		continuation: undefined,
		redirectTo: undefined,
		enrollment: "none",
		emailProof: "not_required",
		acrValues: undefined,
		challenge: undefined,
		pendingEnrollment: undefined,
		attempts: 0,
		sends: 0,
		lastSentAtMs: undefined,
		createdAtMs: 1_767_225_600_000,
		expiresAtMs: 1_767_226_200_000,
		version: 1,
	}) as MfaTransaction;

describe("newMfaTransactionRecord — the binding", () => {
	it.each([
		["a lone high surrogate", "s\uD800"],
		["a lone low surrogate", "s\uDC00"],
		["half a pair at its end", "s\uDBFF"],
		["the halves of a pair, reversed", "s\uDE00\uD83D"],
	])("refuses an id that holds %s", (_label, id) => {
		expect(() => newMfaTransactionRecord(TX({ kind: "session", id }))).toThrow(RangeError);
	});

	it("keeps an id with a well-formed surrogate pair", () => {
		expect(
			newMfaTransactionRecord(TX({ kind: "session", id: "s\uD83D\uDE00" })).binding,
		).toStrictEqual({
			kind: "session",
			id: "s😀",
		});
	});

	it("reads the binding's kind and id once: a getter cannot pass the check and store something else", () => {
		let reads = 0;
		const shifting = {
			kind: "session",
			get id(): unknown {
				reads += 1;
				return reads <= 3 ? "express-session-1" : 7;
			},
		};
		const record = newMfaTransactionRecord(TX(shifting));
		expect(record.binding).toStrictEqual({ kind: "session", id: "express-session-1" });
		expect(reads).toBe(1);
	});

	it("refuses, with a RangeError, a binding whose read throws, rather than letting the throw out", () => {
		for (const throwing of THROWING) {
			expect(() => newMfaTransactionRecord(TX(throwing))).toThrow(RangeError);
		}
		const holder = TX(undefined);
		Object.defineProperty(holder, "binding", {
			get() {
				throw new Error("the transaction's binding getter throws");
			},
		});
		expect(() => newMfaTransactionRecord(holder)).toThrow(RangeError);
	});
});
