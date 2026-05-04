/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import type { ComponentMap } from "@o3co/auth-provider-core";
import { describe, expectTypeOf, it } from "vitest";
import type {
	ChallengeStoreClient,
	DisposableRefreshTokenFamilyClient,
	FederationTokenStoreClient,
	RateLimiterClient,
	RefreshTokenFamilyClient,
	RefreshTokenFamilyMultiClient,
	ReplaySeenSetClient,
	SessionRPRegistryClient,
	SessionRPRegistryMultiClient,
	SessionSidSortedSetClient,
	SessionSidSortedSetMultiClient,
	UserSessionStoreClient,
} from "../src/clients.mjs";
import type { makeIoredisClients } from "../src/ioredis.mjs";

type IoredisClientsReturn = ReturnType<typeof makeIoredisClients>;

describe("makeIoredisClients return shape", () => {
	it("exposes all 9 per-purpose client slots", () => {
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("challengeStoreClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("replaySeenSetClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("refreshTokenFamilyClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("userSessionStoreClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("sessionRPRegistryClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("sessionFamilyIndexClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("sessionFederationIndexClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("federationTokenStoreClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("rateLimiterClient");
	});

	it("challengeStoreClient satisfies ChallengeStoreClient", () => {
		expectTypeOf<
			IoredisClientsReturn["challengeStoreClient"]
		>().toMatchTypeOf<ChallengeStoreClient>();
	});

	it("replaySeenSetClient satisfies ReplaySeenSetClient", () => {
		expectTypeOf<
			IoredisClientsReturn["replaySeenSetClient"]
		>().toMatchTypeOf<ReplaySeenSetClient>();
	});

	it("refreshTokenFamilyClient satisfies RefreshTokenFamilyClient", () => {
		expectTypeOf<
			IoredisClientsReturn["refreshTokenFamilyClient"]
		>().toMatchTypeOf<RefreshTokenFamilyClient>();
	});

	it("userSessionStoreClient satisfies UserSessionStoreClient", () => {
		expectTypeOf<
			IoredisClientsReturn["userSessionStoreClient"]
		>().toMatchTypeOf<UserSessionStoreClient>();
	});

	it("sessionRPRegistryClient satisfies SessionRPRegistryClient", () => {
		expectTypeOf<
			IoredisClientsReturn["sessionRPRegistryClient"]
		>().toMatchTypeOf<SessionRPRegistryClient>();
	});

	it("sessionFamilyIndexClient satisfies SessionSidSortedSetClient", () => {
		expectTypeOf<
			IoredisClientsReturn["sessionFamilyIndexClient"]
		>().toMatchTypeOf<SessionSidSortedSetClient>();
	});

	it("sessionFederationIndexClient satisfies SessionSidSortedSetClient", () => {
		expectTypeOf<
			IoredisClientsReturn["sessionFederationIndexClient"]
		>().toMatchTypeOf<SessionSidSortedSetClient>();
	});

	it("federationTokenStoreClient satisfies FederationTokenStoreClient", () => {
		expectTypeOf<
			IoredisClientsReturn["federationTokenStoreClient"]
		>().toMatchTypeOf<FederationTokenStoreClient>();
	});

	it("rateLimiterClient satisfies RateLimiterClient", () => {
		expectTypeOf<IoredisClientsReturn["rateLimiterClient"]>().toMatchTypeOf<RateLimiterClient>();
	});
});

describe("ComponentMap declaration-merge — per-purpose client slots", () => {
	it("challengeStoreClient slot is optional and of ChallengeStoreClient type", () => {
		expectTypeOf<ComponentMap["challengeStoreClient"]>().toEqualTypeOf<
			ChallengeStoreClient | undefined
		>();
	});

	it("replaySeenSetClient slot is optional and of ReplaySeenSetClient type", () => {
		expectTypeOf<ComponentMap["replaySeenSetClient"]>().toEqualTypeOf<
			ReplaySeenSetClient | undefined
		>();
	});

	it("refreshTokenFamilyClient slot is optional and of RefreshTokenFamilyClient type", () => {
		expectTypeOf<ComponentMap["refreshTokenFamilyClient"]>().toEqualTypeOf<
			RefreshTokenFamilyClient | undefined
		>();
	});

	it("userSessionStoreClient slot is optional and of UserSessionStoreClient type", () => {
		expectTypeOf<ComponentMap["userSessionStoreClient"]>().toEqualTypeOf<
			UserSessionStoreClient | undefined
		>();
	});

	it("sessionRPRegistryClient slot is optional and of SessionRPRegistryClient type", () => {
		expectTypeOf<ComponentMap["sessionRPRegistryClient"]>().toEqualTypeOf<
			SessionRPRegistryClient | undefined
		>();
	});

	it("sessionFamilyIndexClient slot is optional and of SessionSidSortedSetClient type", () => {
		expectTypeOf<ComponentMap["sessionFamilyIndexClient"]>().toEqualTypeOf<
			SessionSidSortedSetClient | undefined
		>();
	});

	it("sessionFederationIndexClient slot is optional and of SessionSidSortedSetClient type", () => {
		expectTypeOf<ComponentMap["sessionFederationIndexClient"]>().toEqualTypeOf<
			SessionSidSortedSetClient | undefined
		>();
	});

	it("federationTokenStoreClient slot is optional and of FederationTokenStoreClient type", () => {
		expectTypeOf<ComponentMap["federationTokenStoreClient"]>().toEqualTypeOf<
			FederationTokenStoreClient | undefined
		>();
	});

	it("rateLimiterClient slot is optional and of RateLimiterClient type", () => {
		expectTypeOf<ComponentMap["rateLimiterClient"]>().toEqualTypeOf<
			RateLimiterClient | undefined
		>();
	});
});

describe("Per-purpose multi-client interfaces", () => {
	it("RefreshTokenFamilyMultiClient has chainable set + exec", () => {
		expectTypeOf<RefreshTokenFamilyMultiClient>().toEqualTypeOf<{
			set(key: string, value: string, mode: "PX", ttlMs: number): RefreshTokenFamilyMultiClient;
			exec(): Promise<unknown[] | null>;
		}>();
	});

	it("DisposableRefreshTokenFamilyClient extends RefreshTokenFamilyClient + AsyncDisposable", () => {
		expectTypeOf<DisposableRefreshTokenFamilyClient>().toMatchTypeOf<RefreshTokenFamilyClient>();
		expectTypeOf<DisposableRefreshTokenFamilyClient>().toMatchTypeOf<AsyncDisposable>();
		expectTypeOf<DisposableRefreshTokenFamilyClient[typeof Symbol.asyncDispose]>().toEqualTypeOf<
			() => Promise<void>
		>();
	});

	it("SessionRPRegistryMultiClient has chainable hSet + pExpireAt + exec", () => {
		expectTypeOf<SessionRPRegistryMultiClient["hSet"]>().toBeFunction();
		expectTypeOf<SessionRPRegistryMultiClient["pExpireAt"]>().toBeFunction();
		expectTypeOf<SessionRPRegistryMultiClient["exec"]>().toBeFunction();
	});

	it("SessionSidSortedSetMultiClient has chainable pExpireAt + zAdd + exec", () => {
		expectTypeOf<SessionSidSortedSetMultiClient["pExpireAt"]>().toBeFunction();
		expectTypeOf<SessionSidSortedSetMultiClient["zAdd"]>().toBeFunction();
		expectTypeOf<SessionSidSortedSetMultiClient["exec"]>().toBeFunction();
	});
});
