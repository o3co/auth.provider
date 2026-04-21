/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";

export interface FederationTokens {
	readonly accessToken: string;
	readonly refreshToken?: string;
	readonly idToken?: string;
	readonly expiresAt: Date;
	readonly tokenType?: string;
	readonly scope?: string;
	readonly rawParams?: Readonly<Record<string, unknown>>;
}

export interface FederationTokenStoreBase {
	readonly kind: string;

	/**
	 * Persist tokens for a session + federation. Implementations MUST encrypt
	 * refreshToken at rest. Plaintext persistence of refresh_token is a
	 * REJECTED implementation. See spec Section 5.
	 */
	attach(sid: string, federationName: string, tokens: FederationTokens): Promise<void>;

	get(sid: string, federationName: string): Promise<FederationTokens | null>;

	/** Atomic replace. Called after a successful federation refresh. */
	update(sid: string, federationName: string, tokens: FederationTokens): Promise<void>;

	/** Delete all federation entries for a session. Idempotent. */
	deleteBySession(sid: string): Promise<void>;

	/** Delete a specific (sid, federationName) entry. Idempotent. */
	delete(sid: string, federationName: string): Promise<void>;
}

export type FederationTokenStoreFactory = AdapterFactory<FederationTokenStoreBase>;
