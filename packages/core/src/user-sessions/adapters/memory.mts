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

type Stored = Omit<UserSession, "claims"> & { claims: Record<string, unknown> };

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
			if (sessions.has(input.sid)) {
				throw new Error(`UserSession ${input.sid} already exists`);
			}
			sessions.set(input.sid, {
				sid: input.sid,
				sub: input.sub,
				authTime: input.authTime,
				createdAt: new Date(),
				expiresAt: input.expiresAt,
				federations: input.federations ?? [],
				activeRPs: [],
				familyIds: [],
				claims: { ...input.claims },
			});
		},
		async get(sid: string): Promise<UserSession | null> {
			const s = readLive(sid);
			if (!s) return null;
			return { ...s, claims: { ...s.claims } as UserSessionClaims };
		},
		async registerRP(sid: string, rp: RegisteredRP) {
			const s = readLive(sid);
			if (!s) return;
			s.activeRPs = [...s.activeRPs.filter((r) => r.clientId !== rp.clientId), rp];
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
			s.claims = { ...s.claims, ...claims };
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
