/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import type { ComponentMap } from "@o3co/auth-provider-core";
import { describe, expectTypeOf, it } from "vitest";
// Import via the package's public entrypoint (not the internal `clients.mjs`)
// so this type-shape test exercises the consumer-facing surface — any drift
// between `index.mts` re-exports and `clients.mts` definitions fails here.
import type {
	AttemptCounterClient,
	ChallengeStoreClient,
	ConsentRecordFields,
	ConsentStoreClient,
	DeviceCodeStoreClient,
	DisposableRefreshTokenFamilyClient,
	FederationGrantStoreClient,
	FederationTokenStoreClient,
	GrantConsentInput,
	MfaFactorStoreClient,
	MfaTransactionStoreClient,
	PendingConsentStoreClient,
	RateLimiterClient,
	RefreshTokenFamilyClient,
	RefreshTokenFamilyMultiClient,
	ReplaySeenSetClient,
	SessionFamilyIndexClient,
	SessionRPRegistryClient,
	SessionRPRegistryMultiClient,
	SessionSidSortedSetClient,
	SessionSidSortedSetMultiClient,
	UserSessionStoreClient,
} from "#/index.mjs";
import type { makeIoredisClients } from "#/ioredis.mjs";

type IoredisClientsReturn = ReturnType<typeof makeIoredisClients>;

describe("makeIoredisClients return shape", () => {
	it("exposes the challenge, replay, refresh-token, session, federation-token, rate-limiter and device-code client slots", () => {
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("challengeStoreClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("deviceCodeStoreClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("replaySeenSetClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("refreshTokenFamilyClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("userSessionStoreClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("sessionRPRegistryClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("sessionFamilyIndexClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("sessionFederationIndexClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("federationTokenStoreClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("rateLimiterClient");
		expectTypeOf<IoredisClientsReturn>().toHaveProperty("attemptCounterClient");
	});

	it("attemptCounterClient satisfies AttemptCounterClient", () => {
		expectTypeOf<
			IoredisClientsReturn["attemptCounterClient"]
		>().toMatchTypeOf<AttemptCounterClient>();
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

	it("sessionFamilyIndexClient satisfies SessionFamilyIndexClient, a SessionSidSortedSetClient", () => {
		expectTypeOf<
			IoredisClientsReturn["sessionFamilyIndexClient"]
		>().toMatchTypeOf<SessionFamilyIndexClient>();
		expectTypeOf<SessionFamilyIndexClient>().toMatchTypeOf<SessionSidSortedSetClient>();
	});

	it("a SessionSidSortedSetClient is a SessionFamilyIndexClient: the mark's two methods are optional", () => {
		expectTypeOf<SessionSidSortedSetClient>().toMatchTypeOf<SessionFamilyIndexClient>();
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

	// FederationTokenStoreClient declares atomic compare-and-delete used
	// by the federation-tokens advisory lock release path. Custom client
	// implementations must add this method.
	it("FederationTokenStoreClient declares compareAndDelete: (key, expected) => Promise<boolean>", () => {
		expectTypeOf<FederationTokenStoreClient["compareAndDelete"]>().toEqualTypeOf<
			(key: string, expectedValue: string) => Promise<boolean>
		>();
	});

	it("rateLimiterClient satisfies RateLimiterClient", () => {
		expectTypeOf<IoredisClientsReturn["rateLimiterClient"]>().toMatchTypeOf<RateLimiterClient>();
	});

	// The device-code store's client is semantic (create / findPending /
	// decide / poll / remove), not a raw `eval` — the Lua stays behind the
	// interface so a custom client can satisfy it with any atomic primitive.
	it("deviceCodeStoreClient satisfies DeviceCodeStoreClient", () => {
		expectTypeOf<
			IoredisClientsReturn["deviceCodeStoreClient"]
		>().toMatchTypeOf<DeviceCodeStoreClient>();
	});

	// The consent stores' clients are semantic too — the union and the
	// one-step consume live behind the interface, not in the caller.
	it("consentStoreClient and pendingConsentStoreClient satisfy their interfaces", () => {
		expectTypeOf<IoredisClientsReturn["consentStoreClient"]>().toMatchTypeOf<ConsentStoreClient>();
		expectTypeOf<
			IoredisClientsReturn["pendingConsentStoreClient"]
		>().toMatchTypeOf<PendingConsentStoreClient>();
	});

	// The MFA ADR's D7, D8: the two MFA stores' clients, off the shared socket.
	it("mfaFactorStoreClient and mfaTransactionStoreClient satisfy their interfaces", () => {
		expectTypeOf<
			IoredisClientsReturn["mfaFactorStoreClient"]
		>().toMatchTypeOf<MfaFactorStoreClient>();
		expectTypeOf<
			IoredisClientsReturn["mfaTransactionStoreClient"]
		>().toMatchTypeOf<MfaTransactionStoreClient>();
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

	it("sessionFamilyIndexClient slot is optional and of SessionFamilyIndexClient type", () => {
		expectTypeOf<ComponentMap["sessionFamilyIndexClient"]>().toEqualTypeOf<
			SessionFamilyIndexClient | undefined
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

	it("attemptCounterClient slot is optional and of AttemptCounterClient type", () => {
		expectTypeOf<ComponentMap["attemptCounterClient"]>().toEqualTypeOf<
			AttemptCounterClient | undefined
		>();
	});

	it("deviceCodeStoreClient slot is optional and of DeviceCodeStoreClient type", () => {
		expectTypeOf<ComponentMap["deviceCodeStoreClient"]>().toEqualTypeOf<
			DeviceCodeStoreClient | undefined
		>();
	});

	it("the consent client slots are optional and of their client types", () => {
		expectTypeOf<ComponentMap["consentStoreClient"]>().toEqualTypeOf<
			ConsentStoreClient | undefined
		>();
		expectTypeOf<ComponentMap["pendingConsentStoreClient"]>().toEqualTypeOf<
			PendingConsentStoreClient | undefined
		>();
	});

	it("the MFA store client slots are optional and of their client types", () => {
		expectTypeOf<ComponentMap["mfaFactorStoreClient"]>().toEqualTypeOf<
			MfaFactorStoreClient | undefined
		>();
		expectTypeOf<ComponentMap["mfaTransactionStoreClient"]>().toEqualTypeOf<
			MfaTransactionStoreClient | undefined
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

	it("SessionRPRegistryMultiClient has chainable hSet + pExpireAt + pExpireGT + exec", () => {
		expectTypeOf<SessionRPRegistryMultiClient["hSet"]>().toBeFunction();
		expectTypeOf<SessionRPRegistryMultiClient["pExpireAt"]>().toBeFunction();
		expectTypeOf<SessionRPRegistryMultiClient["pExpireGT"]>().toBeFunction();
		expectTypeOf<SessionRPRegistryMultiClient["exec"]>().toBeFunction();
	});

	it("SessionSidSortedSetMultiClient has chainable pExpireAt + pExpireGT + zAdd + exec", () => {
		expectTypeOf<SessionSidSortedSetMultiClient["pExpireAt"]>().toBeFunction();
		expectTypeOf<SessionSidSortedSetMultiClient["pExpireGT"]>().toBeFunction();
		expectTypeOf<SessionSidSortedSetMultiClient["zAdd"]>().toBeFunction();
		expectTypeOf<SessionSidSortedSetMultiClient["exec"]>().toBeFunction();
	});
});

/** `true` when `K` must be present on `T` — not merely declared. */
type IsRequiredKey<T, K extends keyof T> = Record<never, never> extends Pick<T, K> ? false : true;

describe("the federation grant client's rotation primitives, as required members", () => {
	// The grant store's take and give-back are required on the port, and the
	// store has nothing to offer them over without these.
	it("FederationGrantStoreClient names takeRotation and refundRotation", () => {
		expectTypeOf<IsRequiredKey<FederationGrantStoreClient, "takeRotation">>().toEqualTypeOf<true>();
		expectTypeOf<
			IsRequiredKey<FederationGrantStoreClient, "refundRotation">
		>().toEqualTypeOf<true>();
	});
});

describe("the consent client's expiry, as a required key", () => {
	// `undefined` here means until revoked — the value that widens what a
	// consent grants — so neither side of the client may arrive at it by
	// leaving the field out: not the store's write, not a client's read.
	it("GrantConsentInput names expiry", () => {
		expectTypeOf<IsRequiredKey<GrantConsentInput, "expiry">>().toEqualTypeOf<true>();
	});

	it("ConsentRecordFields names expiresAt", () => {
		expectTypeOf<IsRequiredKey<ConsentRecordFields, "expiresAt">>().toEqualTypeOf<true>();
	});

	it("tells an optional key from a required one — the control", () => {
		type Probe = { readonly a?: string; readonly b: string | undefined };
		expectTypeOf<IsRequiredKey<Probe, "a">>().toEqualTypeOf<false>();
		expectTypeOf<IsRequiredKey<Probe, "b">>().toEqualTypeOf<true>();
	});
});
