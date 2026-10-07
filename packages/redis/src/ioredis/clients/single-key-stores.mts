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
 * The single-key stores' clients over one ioredis connection: each operation one command on
 * one key.
 */

import type { Redis } from "ioredis";
import type {
	AccessTokenDenylistClient,
	ChallengeStoreClient,
	CodeRepositoryClient,
	ReplaySeenSetClient,
} from "../../clients.mjs";
import { type IoredisDurabilityOptions, redisDurability } from "../durability.mjs";

export function makeIoredisChallengeStoreClient(io: Redis): ChallengeStoreClient {
	const challengeStoreClient: ChallengeStoreClient = {
		set: (k, v, _mode, ttl, _cond) => io.set(k, v, "PX", ttl, "NX") as Promise<"OK" | null>,
		pttl: (k) => io.pttl(k),
		del: (k) => io.del(k),
		get: (k) => io.get(k),
	};
	return challengeStoreClient;
}

export function makeIoredisAccessTokenDenylistClient(
	io: Redis,
	options: IoredisDurabilityOptions = {},
): AccessTokenDenylistClient {
	// Revoked access-token jtis. Plain PX SET (no NX): re-revoking a jti is idempotent, and the
	// last write sets the expiry.
	const accessTokenDenylistClient: AccessTokenDenylistClient = {
		set: (k, v, _mode, ttlMs) => io.set(k, v, "PX", ttlMs) as Promise<"OK">,
		exists: (k) => io.exists(k),
		durability: () => redisDurability(io, options),
	};
	return accessTokenDenylistClient;
}

export function makeIoredisReplaySeenSetClient(
	io: Redis,
	options: IoredisDurabilityOptions = {},
): ReplaySeenSetClient {
	const replaySeenSetClient: ReplaySeenSetClient = {
		set: (k, v, _mode, ttl, _cond) => io.set(k, v, "PX", ttl, "NX") as Promise<"OK" | null>,
		exists: (k) => io.exists(k),
		durability: () => redisDurability(io, options),
	};
	return replaySeenSetClient;
}

export function makeIoredisCodeRepositoryClient(io: Redis): CodeRepositoryClient {
	// Authorization codes: short-lived, high-volume records mapped directly onto ioredis commands.
	const codeRepositoryClient: CodeRepositoryClient = {
		set: (k, v, _mode, ttlMs) => io.set(k, v, "PX", ttlMs) as Promise<"OK">,
		get: (k) => io.get(k),
		getDel: (k) => io.getdel(k),
		del: (k) => io.del(k),
	};
	return codeRepositoryClient;
}
