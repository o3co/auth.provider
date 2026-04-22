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

type Stored = {
	sid: string;
	sub: string;
	authTime: Date;
	createdAt: Date;
	expiresAt: Date;
	federations: string[];
	activeRPs: RegisteredRP[];
	familyIds: string[];
	claims: Record<string, unknown>;
};

/**
 * Deep-copy known array-valued standard claims so callers cannot mutate
 * in-store state by holding onto the original array reference. `groups` is
 * the only known array-valued claim in UserSessionClaims v1; extend this
 * helper when new array-valued claims are added.
 */
const cloneClaims = (c: UserSessionClaims | Record<string, unknown>): Record<string, unknown> => {
	const out: Record<string, unknown> = { ...c };
	const groups = (c as { groups?: unknown }).groups;
	if (Array.isArray(groups)) {
		out.groups = [...groups];
	}
	return out;
};

export function createInMemoryUserSessionStore(): UserSessionStoreBase {
	const sessions = new Map<string, Stored>();

	const readLive = (sid: string): Stored | null => {
		const s = sessions.get(sid);
		if (!s) return null;
		if (s.expiresAt.getTime() <= Date.now()) {
			sessions.delete(sid);
			return null;
		}
		return s;
	};

	return {
		kind: "memory",
		async create(input: CreateUserSessionInput) {
			// GC any expired entry first so duplicate-check semantics match
			// `get()` (which GCs on read). Otherwise a stale expired record
			// would cause create() to throw right after get() returned null.
			if (readLive(input.sid) !== null) {
				throw new Error(`UserSession ${input.sid} already exists`);
			}
			sessions.set(input.sid, {
				sid: input.sid,
				sub: input.sub,
				// Copy Dates so caller-held references cannot mutate stored state.
				authTime: new Date(input.authTime.getTime()),
				createdAt: new Date(),
				expiresAt: new Date(input.expiresAt.getTime()),
				federations: [...(input.federations ?? [])],
				activeRPs: [],
				familyIds: [],
				claims: cloneClaims(input.claims),
			});
		},
		async get(sid: string): Promise<UserSession | null> {
			const s = readLive(sid);
			if (!s) return null;
			// Deep-copy every field that the public `readonly` types promise not to
			// mutate: Dates, array references, and claim object. Without this, a
			// caller doing `(await store.get()).federations.push(...)` (even with
			// a `readonly` cast escape hatch) would mutate the in-store record.
			return {
				sid: s.sid,
				sub: s.sub,
				authTime: new Date(s.authTime.getTime()),
				createdAt: new Date(s.createdAt.getTime()),
				expiresAt: new Date(s.expiresAt.getTime()),
				federations: [...s.federations],
				activeRPs: s.activeRPs.map((r) => ({
					clientId: r.clientId,
					backchannelLogoutUri: r.backchannelLogoutUri,
					backchannelLogoutSessionRequired: r.backchannelLogoutSessionRequired,
					frontchannelLogoutUri: r.frontchannelLogoutUri,
					frontchannelLogoutSessionRequired: r.frontchannelLogoutSessionRequired,
					registeredAt: new Date(r.registeredAt.getTime()),
				})),
				familyIds: [...s.familyIds],
				claims: cloneClaims(s.claims) as UserSessionClaims,
			};
		},
		async registerRP(sid: string, rp: RegisteredRP) {
			const s = readLive(sid);
			if (!s) return;
			// Copy the RP record so caller cannot mutate stored state via its reference.
			const rpCopy: RegisteredRP = {
				clientId: rp.clientId,
				backchannelLogoutUri: rp.backchannelLogoutUri,
				backchannelLogoutSessionRequired: rp.backchannelLogoutSessionRequired,
				frontchannelLogoutUri: rp.frontchannelLogoutUri,
				frontchannelLogoutSessionRequired: rp.frontchannelLogoutSessionRequired,
				registeredAt: new Date(rp.registeredAt.getTime()),
			};
			s.activeRPs = [...s.activeRPs.filter((r) => r.clientId !== rp.clientId), rpCopy];
		},
		async linkFamily(sid: string, familyId: string) {
			const s = readLive(sid);
			if (!s) return;
			if (!s.familyIds.includes(familyId)) {
				s.familyIds = [...s.familyIds, familyId];
			}
		},
		async updateClaims(sid: string, claims: Partial<UserSessionClaims>) {
			const s = readLive(sid);
			if (!s) return;
			// Clone the incoming patch too — if the caller passes { groups: [...] }
			// and later mutates that array, the store must not see the mutation.
			s.claims = cloneClaims({ ...s.claims, ...claims });
		},
		async removeFederation(sid: string, federationName: string) {
			const s = readLive(sid);
			if (!s) return;
			s.federations = s.federations.filter((f) => f !== federationName);
		},
		async delete(sid: string) {
			sessions.delete(sid);
		},
	};
}
