/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import type {
	CreateUserSessionInput,
	RegisteredRP,
	UserSession,
	UserSessionClaims,
	UserSessionStoreBase,
} from "../types.mjs";

/**
 * The subset of the `redis` v5 client used by this adapter. Matching a subset
 * lets us mock the client in tests without importing the real package.
 */
export interface RedisLikeClient {
	get(key: string): Promise<string | null>;
	set(key: string, value: string, opts?: { PX?: number; NX?: boolean }): Promise<string | null>;
	del(key: string): Promise<number>;
}

export interface RedisUserSessionStoreOptions {
	client: RedisLikeClient;
	keyPrefix?: string;
}

interface Envelope {
	sid: string;
	sub: string;
	authTimeMs: number;
	createdAtMs: number;
	expiresAtMs: number;
	federations: string[];
	activeRPs: {
		clientId: string;
		backchannelLogoutUri?: string;
		frontchannelLogoutUri?: string;
		registeredAtMs: number;
	}[];
	familyIds: string[];
	claims: Record<string, unknown>;
}

const toEnvelope = (s: UserSession): Envelope => ({
	sid: s.sid,
	sub: s.sub,
	authTimeMs: s.authTime.getTime(),
	createdAtMs: s.createdAt.getTime(),
	expiresAtMs: s.expiresAt.getTime(),
	federations: [...s.federations],
	activeRPs: s.activeRPs.map((r) => ({
		clientId: r.clientId,
		backchannelLogoutUri: r.backchannelLogoutUri,
		frontchannelLogoutUri: r.frontchannelLogoutUri,
		registeredAtMs: r.registeredAt.getTime(),
	})),
	familyIds: [...s.familyIds],
	claims: { ...s.claims },
});

const fromEnvelope = (e: Envelope): UserSession => ({
	sid: e.sid,
	sub: e.sub,
	authTime: new Date(e.authTimeMs),
	createdAt: new Date(e.createdAtMs),
	expiresAt: new Date(e.expiresAtMs),
	federations: e.federations,
	activeRPs: e.activeRPs.map((r) => ({
		clientId: r.clientId,
		backchannelLogoutUri: r.backchannelLogoutUri,
		frontchannelLogoutUri: r.frontchannelLogoutUri,
		registeredAt: new Date(r.registeredAtMs),
	})),
	familyIds: e.familyIds,
	claims: e.claims as UserSessionClaims,
});

export function createRedisUserSessionStore(
	opts: RedisUserSessionStoreOptions,
): UserSessionStoreBase {
	const prefix = opts.keyPrefix ?? "us:";
	const k = (sid: string) => `${prefix}${sid}`;

	const loadEnvelope = async (sid: string): Promise<Envelope | null> => {
		const v = await opts.client.get(k(sid));
		if (!v) return null;
		try {
			return JSON.parse(v) as Envelope;
		} catch {
			return null;
		}
	};

	const writeEnvelope = async (env: Envelope, nx = false): Promise<string | null> => {
		const remaining = env.expiresAtMs - Date.now();
		if (remaining <= 0) return null;
		return opts.client.set(k(env.sid), JSON.stringify(env), { PX: remaining, NX: nx });
	};

	return {
		kind: "redis",
		async create(input: CreateUserSessionInput) {
			const session: UserSession = {
				sid: input.sid,
				sub: input.sub,
				authTime: input.authTime,
				createdAt: new Date(),
				expiresAt: input.expiresAt,
				federations: input.federations ?? [],
				activeRPs: [],
				familyIds: [],
				claims: { ...input.claims },
			};
			const result = await writeEnvelope(toEnvelope(session), true);
			if (result === null) throw new Error(`UserSession ${input.sid} already exists`);
		},
		async get(sid) {
			const env = await loadEnvelope(sid);
			return env ? fromEnvelope(env) : null;
		},
		async registerRP(sid, rp: RegisteredRP) {
			const env = await loadEnvelope(sid);
			if (!env) return;
			env.activeRPs = [
				...env.activeRPs.filter((r) => r.clientId !== rp.clientId),
				{
					clientId: rp.clientId,
					backchannelLogoutUri: rp.backchannelLogoutUri,
					frontchannelLogoutUri: rp.frontchannelLogoutUri,
					registeredAtMs: rp.registeredAt.getTime(),
				},
			];
			await writeEnvelope(env);
		},
		async linkFamily(sid, familyId) {
			const env = await loadEnvelope(sid);
			if (!env) return;
			if (!env.familyIds.includes(familyId)) env.familyIds = [...env.familyIds, familyId];
			await writeEnvelope(env);
		},
		async updateClaims(sid, claims: Partial<UserSessionClaims>) {
			const env = await loadEnvelope(sid);
			if (!env) return;
			env.claims = { ...env.claims, ...claims };
			await writeEnvelope(env);
		},
		async removeFederation(sid, federationName) {
			const env = await loadEnvelope(sid);
			if (!env) return;
			env.federations = env.federations.filter((f) => f !== federationName);
			await writeEnvelope(env);
		},
		async delete(sid) {
			await opts.client.del(k(sid));
		},
	};
}
