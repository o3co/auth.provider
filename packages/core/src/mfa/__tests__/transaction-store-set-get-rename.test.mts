/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe, expect, it } from "vitest";
import type { MfaPendingTransaction } from "../types.mjs";
import { createInMemoryTransactionStore } from "./fixtures.mjs";

const sampleTx: MfaPendingTransaction = {
	transactionId: "tx-1",
	flow: "authorize",
	subject: "user-1",
	providerKind: "totp",
	challengeId: "ch-1",
	expiresAt: new Date(Date.now() + 5 * 60 * 1000),
	resumeState: {
		flow: "authorize",
		clientId: "client-1",
		redirectUri: "https://app.example/cb",
		responseType: "code",
	},
};

describe("AS-11: MfaTransactionStore.save/load → set/get (BREAKING rename)", () => {
	it("in-memory store exposes set", () => {
		const store = createInMemoryTransactionStore();
		expect("set" in store).toBe(true);
	});

	it("in-memory store exposes get", () => {
		const store = createInMemoryTransactionStore();
		expect("get" in store).toBe(true);
	});

	it("in-memory store no longer exposes save", () => {
		const store = createInMemoryTransactionStore();
		expect("save" in store).toBe(false);
	});

	it("in-memory store no longer exposes load", () => {
		const store = createInMemoryTransactionStore();
		expect("load" in store).toBe(false);
	});

	it("set/get round-trips a pending transaction (functional parity with old save/load)", async () => {
		const store = createInMemoryTransactionStore();
		await store.set(sampleTx);
		expect(await store.get(sampleTx.transactionId)).toEqual(sampleTx);
	});

	it("get returns null for unknown transactionId", async () => {
		const store = createInMemoryTransactionStore();
		expect(await store.get("missing")).toBeNull();
	});
});
