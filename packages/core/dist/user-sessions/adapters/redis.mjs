/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
const toEnvelope = (s) => ({
    sid: s.sid,
    sub: s.sub,
    authTimeMs: s.authTime.getTime(),
    createdAtMs: s.createdAt.getTime(),
    expiresAtMs: s.expiresAt.getTime(),
    federations: [...s.federations],
    activeRPs: s.activeRPs.map((r) => ({
        clientId: r.clientId,
        backchannelLogoutUri: r.backchannelLogoutUri,
        backchannelLogoutSessionRequired: r.backchannelLogoutSessionRequired,
        frontchannelLogoutUri: r.frontchannelLogoutUri,
        frontchannelLogoutSessionRequired: r.frontchannelLogoutSessionRequired,
        registeredAtMs: r.registeredAt.getTime(),
    })),
    familyIds: [...s.familyIds],
    claims: { ...s.claims },
});
const fromEnvelope = (e) => ({
    sid: e.sid,
    sub: e.sub,
    authTime: new Date(e.authTimeMs),
    createdAt: new Date(e.createdAtMs),
    expiresAt: new Date(e.expiresAtMs),
    federations: e.federations,
    activeRPs: e.activeRPs.map((r) => ({
        clientId: r.clientId,
        backchannelLogoutUri: r.backchannelLogoutUri,
        backchannelLogoutSessionRequired: r.backchannelLogoutSessionRequired,
        frontchannelLogoutUri: r.frontchannelLogoutUri,
        frontchannelLogoutSessionRequired: r.frontchannelLogoutSessionRequired,
        registeredAt: new Date(r.registeredAtMs),
    })),
    familyIds: e.familyIds,
    claims: e.claims,
});
export function createRedisUserSessionStore(opts) {
    const prefix = opts.keyPrefix ?? "us:";
    const k = (sid) => `${prefix}${sid}`;
    const loadEnvelope = async (sid) => {
        const v = await opts.client.get(k(sid));
        if (!v)
            return null;
        try {
            return JSON.parse(v);
        }
        catch {
            // Corrupt/non-JSON payload: self-heal by deleting the key so subsequent
            // create(sid) doesn't fail NX with a misleading "already exists" error,
            // and subsequent get(sid) stays consistently null.
            await opts.client.del(k(sid));
            return null;
        }
    };
    const writeEnvelope = async (env, nx = false) => {
        const remaining = env.expiresAtMs - Date.now();
        if (remaining <= 0)
            return "ttl_expired";
        const result = await opts.client.set(k(env.sid), JSON.stringify(env), {
            PX: remaining,
            NX: nx,
        });
        return result === null ? "nx_failed" : "ok";
    };
    return {
        kind: "redis",
        async create(input) {
            // Validate expiresAt up-front so an already-expired input fails with a
            // clear message rather than being misdiagnosed as a duplicate-sid error
            // when writeEnvelope returns null for non-positive TTL.
            if (input.expiresAt.getTime() <= Date.now()) {
                throw new Error(`UserSession ${input.sid}: expiresAt is in the past (TTL must be positive)`);
            }
            const session = {
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
            if (result === "nx_failed") {
                throw new Error(`UserSession ${input.sid} already exists`);
            }
            if (result === "ttl_expired") {
                // Upstream expiresAt > now check (above) should prevent this, but a
                // small racy window (clock skew, slow call) can still hit it. Surface
                // a clear error rather than a misleading "already exists".
                throw new Error(`UserSession ${input.sid}: expiresAt elapsed before Redis SET could run (clock skew or delay)`);
            }
        },
        async get(sid) {
            const env = await loadEnvelope(sid);
            return env ? fromEnvelope(env) : null;
        },
        async registerRP(sid, rp) {
            const env = await loadEnvelope(sid);
            if (!env)
                return;
            env.activeRPs = [
                ...env.activeRPs.filter((r) => r.clientId !== rp.clientId),
                {
                    clientId: rp.clientId,
                    backchannelLogoutUri: rp.backchannelLogoutUri,
                    backchannelLogoutSessionRequired: rp.backchannelLogoutSessionRequired,
                    frontchannelLogoutUri: rp.frontchannelLogoutUri,
                    frontchannelLogoutSessionRequired: rp.frontchannelLogoutSessionRequired,
                    registeredAtMs: rp.registeredAt.getTime(),
                },
            ];
            await writeEnvelope(env);
        },
        async linkFamily(sid, familyId) {
            const env = await loadEnvelope(sid);
            if (!env)
                return;
            if (!env.familyIds.includes(familyId))
                env.familyIds = [...env.familyIds, familyId];
            await writeEnvelope(env);
        },
        async updateClaims(sid, claims) {
            const env = await loadEnvelope(sid);
            if (!env)
                return;
            env.claims = { ...env.claims, ...claims };
            await writeEnvelope(env);
        },
        async removeFederation(sid, federationName) {
            const env = await loadEnvelope(sid);
            if (!env)
                return;
            env.federations = env.federations.filter((f) => f !== federationName);
            await writeEnvelope(env);
        },
        async delete(sid) {
            await opts.client.del(k(sid));
        },
    };
}
