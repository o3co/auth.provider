/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
/*
 * The `@o3co/auth-provider-redis/ioredis` entry: `makeIoredisClients`, which builds the
 * single-connection set from each store family's client in `./ioredis/clients/`, and the
 * separate factories for the federation grant, federation grant intent and MFA stores. A subpath
 * of its own, so the main entry never pulls ioredis types into a consumer's dependency closure.
 */
import { consoleLogger, type EventLogger } from "@o3co/auth-provider-core";
import type { Redis } from "ioredis";
import type {
	AccessTokenDenylistClient,
	ChallengeStoreClient,
	CodeRepositoryClient,
	ConsentStoreClient,
	DeviceCodeStoreClient,
	FederationTokenStoreClient,
	MfaFactorStoreClient,
	MfaTransactionStoreClient,
	PendingConsentStoreClient,
	RateLimiterClient,
	RefreshTokenFamilyClient,
	ReplaySeenSetClient,
	SessionFamilyIndexClient,
	SessionRPRegistryClient,
	SessionSidSortedSetClient,
	SubjectRevocationClient,
	SubjectSessionIndexClient,
	UserSessionStoreClient,
} from "./clients.mjs";
import {
	makeIoredisConsentStoreClient,
	makeIoredisPendingConsentStoreClient,
} from "./ioredis/clients/consent.mjs";
import { makeIoredisDeviceCodeStoreClient } from "./ioredis/clients/device-code.mjs";
import { makeIoredisFederationTokenStoreClient } from "./ioredis/clients/federation-tokens.mjs";
import {
	makeIoredisMfaFactorStoreClient,
	makeIoredisMfaTransactionStoreClient,
} from "./ioredis/clients/mfa.mjs";
import { makeIoredisRateLimiterClient } from "./ioredis/clients/rate-limiter.mjs";
import { makeIoredisRefreshTokenFamilyClient } from "./ioredis/clients/refresh-token-family.mjs";
import {
	makeIoredisAccessTokenDenylistClient,
	makeIoredisChallengeStoreClient,
	makeIoredisCodeRepositoryClient,
	makeIoredisReplaySeenSetClient,
} from "./ioredis/clients/single-key-stores.mjs";
import {
	makeIoredisSessionFamilyIndexClient,
	makeIoredisSessionRPRegistryClient,
	makeIoredisSessionSidSortedSetClient,
	makeIoredisSubjectRevocationClient,
	makeIoredisSubjectSessionIndexClient,
	makeIoredisUserSessionStoreClient,
} from "./ioredis/clients/user-sessions.mjs";

export {
	type FederationGrantRedisCommands,
	makeIoredisFederationGrantStoreClient,
} from "./ioredis/clients/federation-grant.mjs";

export {
	type FederationGrantIntentRedisCommands,
	makeIoredisFederationGrantIntentStoreClient,
} from "./ioredis/clients/federation-grant-intent.mjs";

export { makeIoredisMfaFactorStoreClient, makeIoredisMfaTransactionStoreClient };

/** Options for {@link makeIoredisClients}. */
export interface IoredisClientsOptions {
	/**
	 * Where errors from connections the wrapper opens itself (the refresh-token family's
	 * `duplicate()`) are reported; defaults to `consoleLogger`. An `EventLogger` rather than a
	 * `Logger`, so a composition root can pass its host logger. The `io` connection, its
	 * lifetime and its listeners stay the caller's; see the README for the listener it needs.
	 */
	readonly logger?: EventLogger;
}

/**
 * Wraps one ioredis connection into the typed clients the `@o3co/auth-provider-redis` adapters
 * need; a composition root spreads the result into `bootstrapComponents`, or wires slots one by
 * one for a mixed-backend deployment.
 *
 * Every client uses `io`; the only connection opened here is the per-rotation
 * `refreshTokenFamilyClient.duplicate()`. Connection options are therefore shared by every
 * purpose, and one that needs different failure timing (`enableOfflineQueue: false` for the
 * rate limiter, say) needs a connection of its own.
 */
export function makeIoredisClients(
	io: Redis,
	options: IoredisClientsOptions = {},
): {
	challengeStoreClient: ChallengeStoreClient;
	accessTokenDenylistClient: AccessTokenDenylistClient;
	replaySeenSetClient: ReplaySeenSetClient;
	refreshTokenFamilyClient: RefreshTokenFamilyClient;
	userSessionStoreClient: UserSessionStoreClient;
	sessionRPRegistryClient: SessionRPRegistryClient;
	sessionFamilyIndexClient: SessionFamilyIndexClient;
	sessionFederationIndexClient: SessionSidSortedSetClient;
	subjectSessionIndexClient: SubjectSessionIndexClient;
	subjectRevocationClient: SubjectRevocationClient;
	federationTokenStoreClient: FederationTokenStoreClient;
	rateLimiterClient: RateLimiterClient;
	codeRepositoryClient: CodeRepositoryClient;
	deviceCodeStoreClient: DeviceCodeStoreClient;
	consentStoreClient: ConsentStoreClient;
	pendingConsentStoreClient: PendingConsentStoreClient;
	mfaFactorStoreClient: MfaFactorStoreClient;
	mfaTransactionStoreClient: MfaTransactionStoreClient;
} {
	const logger = options.logger ?? consoleLogger;

	const challengeStoreClient = makeIoredisChallengeStoreClient(io);
	const accessTokenDenylistClient = makeIoredisAccessTokenDenylistClient(io);
	const replaySeenSetClient = makeIoredisReplaySeenSetClient(io);
	const refreshTokenFamilyClient = makeIoredisRefreshTokenFamilyClient(io, logger);
	const userSessionStoreClient = makeIoredisUserSessionStoreClient(io);
	const sessionRPRegistryClient = makeIoredisSessionRPRegistryClient(io);
	const sortedSetClient = makeIoredisSessionSidSortedSetClient(io);
	const sessionFamilyIndexClient = makeIoredisSessionFamilyIndexClient(io);
	const subjectSessionIndexClient = makeIoredisSubjectSessionIndexClient(io);
	const subjectRevocationClient = makeIoredisSubjectRevocationClient(io);
	const federationTokenStoreClient = makeIoredisFederationTokenStoreClient(io);
	const rateLimiterClient = makeIoredisRateLimiterClient(io);
	const codeRepositoryClient = makeIoredisCodeRepositoryClient(io);
	const deviceCodeStoreClient = makeIoredisDeviceCodeStoreClient(io);
	const consentStoreClient = makeIoredisConsentStoreClient(io);
	const pendingConsentStoreClient = makeIoredisPendingConsentStoreClient(io);

	return {
		challengeStoreClient,
		accessTokenDenylistClient,
		replaySeenSetClient,
		refreshTokenFamilyClient,
		userSessionStoreClient,
		sessionRPRegistryClient,
		sessionFamilyIndexClient,
		sessionFederationIndexClient: sortedSetClient,
		subjectSessionIndexClient,
		subjectRevocationClient,
		federationTokenStoreClient,
		rateLimiterClient,
		codeRepositoryClient,
		deviceCodeStoreClient,
		consentStoreClient,
		pendingConsentStoreClient,
		mfaFactorStoreClient: makeIoredisMfaFactorStoreClient(io),
		mfaTransactionStoreClient: makeIoredisMfaTransactionStoreClient(io),
	};
}
