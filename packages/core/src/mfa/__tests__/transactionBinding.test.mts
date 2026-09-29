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
 * What an MFA transaction is bound to (#742): a typed binding, not a bare
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
		expect(true).toBe(true);
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
});
