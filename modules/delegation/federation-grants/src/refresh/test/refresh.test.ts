import { Unavailable } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import type { Seal } from "@mod/seal";
import { type Delegation, type UpstreamRefresh, UpstreamRefused } from "@mod/upstreams";
import { describe, expect, it, vi } from "vitest";
import { memoryStores } from "../../../test/stores.ts";
import { type Grant, recordsWith, withoutCredentials } from "../../grant/grant.ts";
import type { RefreshLockStore } from "../../store.ts";
import { type Current, refreshWith } from "../refresh.ts";

const shown = ["openid", "offline_access", "read"];
const day = 86_400_000;

/** A seal that opens only under the context it sealed for. */
const seal: Seal = {
	seal: (plain, context) => JSON.stringify([context, plain]),
	open: (sealed, context) => {
		const [bound, plain] = JSON.parse(sealed) as [string, string];
		return bound === context ? { kind: "opened", plain } : { kind: "refused" };
	},
};

/** Tokens an upstream gives, bearer with a refresh token and five minutes, unless said. */
const upstreamTokens = (more: Readonly<Record<string, unknown>> = {}) => ({
	accessToken: "up-1",
	tokenType: "Bearer",
	refreshToken: "up-refresh-1",
	expiresInSeconds: 300,
	scope: shown,
	...more,
});

/** An outcome in a line: its kind, then the token handed, the reason or the retry-after. */
const said = (current: Current) =>
	[
		current.kind,
		current.kind === "handed" ? current.accessToken : undefined,
		"reason" in current ? current.reason : undefined,
		current.kind === "limited" ? current.retryAfterSeconds : undefined,
	]
		.filter((part) => part !== undefined)
		.join(" ");

/** Another holder lets go of the grant's lock at once, whatever mark it holds. */
const letGo = (locks: RefreshLockStore) =>
	locks.update("g", (held) => ({ value: held, lifetimeMs: 0 }));

type Upstream =
	| UpstreamRefresh
	| "unreachable"
	| "refused"
	| (() => UpstreamRefresh | Promise<UpstreamRefresh>);

/**
 * The refresher over memory stores on a test clock, and an active grant `g` holding an upstream
 * token of `life` seconds obtained now.
 */
async function refresher(life: number, settings: { rotations?: number; windowMs?: number } = {}) {
	let now = 1_800_000_000_000;
	const stores = memoryStores(() => now);
	const records = recordsWith(seal);
	const logged = recordingLog();
	const runtime = quietRuntime({ clock: { now: () => now }, log: logged.log });
	/** Whether the subject's boundary ends the grant, and when the grant ends, as the grants' judge would answer. */
	const boundary: { revoked: boolean; endsAt?: number } = { revoked: false };
	const refresh = refreshWith({
		grants: stores.grants,
		locks: stores.lockStore,
		records,
		revoked: async () => boundary.revoked,
		endOf: () => boundary.endsAt,
		...runtime,
		refreshBeforeMs: 30_000,
		rotations: settings.rotations ?? 24,
		rotationWindowMs: settings.windowMs ?? 3_600_000,
	});
	const upstream: Upstream[] = [];
	const asked: [string, readonly string[], string | undefined][] = [];
	const delegation = {
		refresh: async (token, scope, resource) => {
			asked.push([token, scope, resource]);
			const next = upstream.shift();
			if (next === "unreachable") throw new Unavailable("test upstream");
			if (next === "refused") throw new UpstreamRefused();
			if (typeof next === "function") return next();
			const fresh = upstreamTokens({ accessToken: `up-${asked.length + 1}` });
			return next ?? ({ kind: "refreshed", tokens: fresh } as UpstreamRefresh);
		},
	} as Delegation;
	const grant: Grant = {
		format: 1,
		id: "g",
		client: "worker",
		subject: "alice",
		connection: "cal",
		status: "active",
		createdAt: now,
		scopes: shown,
		authorizedAt: now,
		expiresAt: now + day,
		version: "v-0",
		rotations: { from: now, count: 0 },
	};
	const sealed = records.seal(grant, {
		accessToken: "up-1",
		tokenType: "Bearer",
		refreshToken: "up-refresh-1",
		expiresAt: now + life * 1000,
		obtainedAt: now,
		scope: shown,
	});
	await stores.grants.create("g", records.stored({ ...grant, sealed }), 30 * day);
	/** The grant as stored now. */
	const stored = async () => records.grantOf(await stores.grants.read("g"));

	return {
		stores,
		records,
		boundary,
		upstream,
		asked,
		logs: () => logged.lines(),
		stored,
		/** Asks for the token as a client's request does, from the grant read first. */
		call: async (more: { scope?: readonly string[]; minTtlMs?: number; resource?: string } = {}) =>
			refresh.current((await stored()) as Grant, {
				delegation,
				maxAccessMs: 3_600_000,
				minTtlMs: 0,
				grantEndsAt: now + day,
				...more,
			}),
		advance: (ms: number) => {
			now += ms;
		},
	};
}

/** A refreshed token of four seconds that carries only `openid`. */
const narrow = { tokens: { accessToken: "narrow", expiresInSeconds: 4, scope: ["openid"] } };

/** Calls in order, each after time moves on, with what it asks and what it comes to. */
const refreshCases: readonly {
	readonly name: string;
	readonly settings?: { rotations?: number; windowMs?: number };
	/** The upstream token's life at activation, in seconds. */
	readonly life: number;
	readonly upstream?: readonly (Upstream | { readonly tokens: Record<string, unknown> })[];
	readonly calls: readonly {
		readonly advance?: number;
		readonly asked?: { scope?: readonly string[]; minTtlMs?: number };
		readonly said: string;
	}[];
	/** The scopes each upstream refresh asked for, in order. */
	readonly asked?: readonly (readonly string[])[];
}[] = [
	{
		name: "serves a held token with exactly a second left when the refresh cannot",
		life: 4,
		upstream: ["unreachable"],
		calls: [{ advance: 3000, said: "handed up-1" }],
	},
	{
		name: "refreshes a token of one second as soon as less than a second is left",
		life: 1,
		calls: [{ advance: 1, said: "handed up-2" }],
	},
	{
		name: "refreshes at exactly half its life",
		life: 4,
		calls: [{ advance: 2000, said: "handed up-2" }],
	},
	{
		name: "refreshes with exactly refresh-before left",
		life: 60,
		calls: [{ advance: 30_000, said: "handed up-2" }],
	},
	{
		name: "refreshes with exactly min_ttl left",
		life: 400,
		calls: [{ advance: 210_000, asked: { minTtlMs: 190_000 }, said: "handed up-2" }],
	},
	{
		name: "asks the upstream for the scopes shown, not those asked, and judges the answer by them",
		life: 4,
		calls: [{ advance: 2100, asked: { scope: ["read"] }, said: "handed up-2" }],
		asked: [shown],
	},
	{
		name: "refreshes a held token lacking an asked scope once half its life is spent",
		life: 4,
		upstream: [{ tokens: { accessToken: "narrow", expiresInSeconds: 100, scope: ["openid"] } }],
		calls: [
			{ advance: 2100, said: "handed narrow" },
			{ advance: 60_000, asked: { scope: ["read"] }, said: "handed up-3" },
		],
	},
	{
		name: "refreshes again exactly when the rotation window closes",
		life: 4,
		settings: { rotations: 1, windowMs: 600_000 },
		calls: [
			{ advance: 2100, said: "handed up-2" },
			{ advance: 597_900, said: "handed up-3" },
		],
	},
	{
		name: "hands no held token lacking an asked scope when the refresh cannot",
		life: 4,
		upstream: [narrow, "unreachable"],
		calls: [
			{ advance: 2100, said: "handed narrow" },
			{ advance: 2100, asked: { scope: ["read"] }, said: "unavailable" },
		],
	},
	{
		name: "refuses a scope a held token lacks while it is not due",
		life: 4,
		upstream: [narrow],
		calls: [
			{ advance: 2100, said: "handed narrow" },
			{ asked: { scope: ["read"] }, said: "scope" },
		],
	},
	{
		name: "refuses a refreshed token narrower than asked",
		life: 4,
		upstream: [narrow],
		calls: [{ advance: 2100, asked: { scope: ["read"] }, said: "scope" }],
	},
	{
		name: "hands the held token while the upstream is unreachable, and refreshes after",
		life: 4,
		upstream: ["unreachable"],
		calls: [{ advance: 2100, said: "handed up-1" }, { said: "handed up-3" }],
	},
	{
		name: "answers the upstream unreachable once the held token has ended",
		life: 4,
		upstream: ["unreachable"],
		calls: [{ advance: 4100, said: "unavailable" }],
	},
	{
		name: "hands the held token while the upstream is refused, and refreshes after",
		life: 4,
		upstream: ["refused"],
		calls: [{ advance: 2100, said: "handed up-1" }, { said: "handed up-3" }],
	},
	{
		name: "answers the upstream refused once the held token has ended",
		life: 4,
		upstream: ["refused"],
		calls: [{ advance: 4100, said: "refused" }],
	},
	{
		name: "hands the held token while the upstream is limited, and refreshes after",
		life: 4,
		upstream: [{ kind: "limited", retryAfterSeconds: 7 }],
		calls: [{ advance: 2100, said: "handed up-1" }, { said: "handed up-3" }],
	},
	{
		name: "answers the upstream limited, with its retry-after, once the held token has ended",
		life: 4,
		upstream: [{ kind: "limited", retryAfterSeconds: 7 }],
		calls: [{ advance: 4100, said: "limited 7" }],
	},
	{
		name: "does not refresh before half its life, even near its end",
		life: 40,
		calls: [
			{ advance: 15_000, said: "handed up-1" },
			{ asked: { minTtlMs: 30_000 }, said: "handed up-1" },
			{ advance: 6000, asked: { minTtlMs: 30_000 }, said: "handed up-2" },
		],
	},
	{
		name: "keeps a narrower answer, and asks for the scopes shown at the next refresh",
		life: 4,
		upstream: [narrow],
		calls: [
			{ advance: 2100, said: "handed narrow" },
			{ advance: 2100, said: "handed up-3" },
		],
		asked: [shown, shown],
	},
	{
		name: "takes at most the rotations of a window, then hands the held token or limits until it closes",
		life: 4,
		settings: { rotations: 2, windowMs: 60_000 },
		upstream: [
			{ tokens: { accessToken: "up-2", expiresInSeconds: 4 } },
			{ tokens: { accessToken: "up-3", expiresInSeconds: 4 } },
		],
		calls: [
			{ advance: 2100, said: "handed up-2" },
			{ advance: 2100, said: "handed up-3" },
			{ advance: 2100, said: "handed up-3" },
			{ advance: 2000, said: "limited 52" },
			{ advance: 60_000, said: "handed up-4" },
		],
		asked: [shown, shown, shown],
	},
	{
		name: "keeps the held refresh token when the upstream sends none",
		life: 4,
		upstream: [{ tokens: { refreshToken: undefined, accessToken: "kept" } }],
		calls: [{ advance: 2100, said: "handed kept" }],
	},
	{
		name: "serves the held token that still lives when the refreshed one cannot be held",
		life: 4,
		upstream: [{ tokens: { tokenType: "DPoP" } }],
		calls: [{ advance: 2100, said: "handed up-1" }],
	},
];

describe("refresh scenes", () => {
	for (const scene of refreshCases) {
		it(scene.name, async () => {
			const r = await refresher(scene.life, scene.settings);
			for (const next of scene.upstream ?? []) {
				const tokens = typeof next === "object" && "tokens" in next ? next.tokens : undefined;
				r.upstream.push(
					tokens
						? {
								kind: "refreshed",
								tokens: upstreamTokens(tokens as Record<string, unknown>) as never,
							}
						: (next as Upstream),
				);
			}
			for (const call of scene.calls) {
				r.advance(call.advance ?? 0);
				expect(said(await r.call(call.asked))).toBe(call.said);
			}
			if (scene.asked) expect(r.asked.map(([, scope]) => scope)).toEqual(scene.asked);
		});
	}
});

describe("refreshing a grant's token", () => {
	it("hands a fresh token without asking the upstream, and refreshes one due for the resource", async () => {
		const r = await refresher(4);
		expect(said(await r.call())).toBe("handed up-1");
		r.advance(2100);
		const resource = "https://api.example/";
		expect(await r.call({ resource })).toMatchObject({ accessToken: "up-2", refreshed: true });
		expect(r.asked).toEqual([["up-refresh-1", shown, resource]]);
		expect(said(await r.call())).toBe("handed up-2");
		expect(r.asked.length).toBe(1);
	});

	it("ends the credential when the upstream asks the user to act there first, under its own reason", async () => {
		const r = await refresher(4);
		r.advance(2100);
		r.upstream.push({ kind: "interaction_required" });
		expect(said(await r.call())).toBe("reauthorize upstream_interaction_required");
		const ended = await r.stored();
		expect(ended).toMatchObject({
			status: "reauthorization_required",
			reason: "upstream_interaction_required",
		});
		expect(ended).not.toHaveProperty("sealed");
	});

	it("ends the credential only on a structured invalid_grant", async () => {
		const r = await refresher(4);
		r.advance(2100);
		r.upstream.push({ kind: "invalid_grant" });
		expect(said(await r.call())).toBe("reauthorize upstream_invalid_grant");
		const ended = await r.stored();
		expect(ended).toMatchObject({ status: "reauthorization_required" });
		expect(ended).not.toHaveProperty("sealed");
	});

	it("hands no held token while the end an upstream asked could not be written, until that token ends", async () => {
		for (const [kind, reason] of [
			["invalid_grant", "upstream_invalid_grant"],
			["interaction_required", "upstream_interaction_required"],
		] as const) {
			const r = await refresher(300);
			r.advance(151_000);
			r.upstream.push(() => {
				r.stores.down.failNext("change");
				return { kind } as UpstreamRefresh;
			});
			// Due only for the time it asks: the end cannot be written, and the store's outage is told.
			await expect(r.call({ minTtlMs: 200_000 }), kind).rejects.toThrow();
			expect(await r.stored(), kind).toMatchObject({ status: "active" });
			// A request the held token would serve is refused as the upstream answered, not handed it.
			expect(said(await r.call()), kind).toBe(`reauthorize ${reason}`);
			expect(r.asked, kind).toHaveLength(1);
			// Once that token has ended, the upstream is asked again, and the end written.
			r.advance(150_000);
			r.upstream.push({ kind });
			expect(said(await r.call()), kind).toBe(`reauthorize ${reason}`);
			expect(await r.stored(), kind).toMatchObject({ status: "reauthorization_required" });
		}
	});

	it("writes a rotated refresh token before it judges the rest, and marks a token it cannot hold", async () => {
		const r = await refresher(4);
		r.advance(4100);
		r.upstream.push({
			kind: "refreshed",
			tokens: upstreamTokens({ tokenType: "DPoP", refreshToken: "rotated" }) as never,
		});
		expect(said(await r.call())).toBe("ineligible upstream_token_ineligible");
		expect(await r.stored()).toMatchObject({
			status: "upstream_token_ineligible",
			reason: "upstream_token_ineligible",
		});
		expect(r.logs()).toContainEqual({
			level: "warn",
			event: "federation-grants.refresh_ineligible",
			fields: { reason: "upstream_token_ineligible" },
		});
		expect(said(await r.call())).toBe("handed up-3");
		expect(r.asked.map(([token]) => token)).toEqual(["up-refresh-1", "rotated"]);
		expect(await r.stored()).toMatchObject({ status: "active" });
		expect(await r.stored()).not.toHaveProperty("reason");
	});

	it("asks the upstream nothing for credentials that do not open", async () => {
		const r = await refresher(4);
		await r.stores.grants.change("g", (g) => ({ value: { ...g, sealed: "[]" } as never }));
		expect(said(await r.call())).toBe("reauthorize credentials_unreadable");
		expect(r.asked).toEqual([]);
	});
});

describe("refreshing alongside other writers", () => {
	it("refreshes nothing over a grant another writer rewrote since it was read", async () => {
		const r = await refresher(4);
		r.advance(2100);
		r.stores.raceNext((record) => ({ ...(record as object), version: "another" }) as never);
		expect(said(await r.call())).toBe("gone");
		expect(r.asked).toEqual([]);
		expect(r.stores.peek("g")).toMatchObject({ version: "another" });
	});

	it("answers gone when a revocation lands between the rotation and what the upstream said", async () => {
		for (const answer of [
			{ kind: "invalid_grant" },
			{ kind: "refreshed", tokens: upstreamTokens({ tokenType: "DPoP" }) },
			{ kind: "refreshed", tokens: upstreamTokens() },
		] as const) {
			const r = await refresher(4);
			r.advance(2100);
			r.upstream.push(() => {
				r.stores.raceNext((record) => ({ ...(record as object), status: "revoked" }) as never);
				return answer as never;
			});
			expect(said(await r.call()), answer.kind).toBe("gone");
			expect(r.stores.peek("g")).toMatchObject({ status: "revoked" });
		}
	});

	it("passes on an upstream fault that is no outage", async () => {
		const r = await refresher(4);
		r.advance(2100);
		r.upstream.push(() => {
			throw new TypeError("not now");
		});
		await expect(r.call()).rejects.toThrow(TypeError);
	});

	it("waits for another holder's lock for half its life, then hands what still lives", async () => {
		vi.useFakeTimers({ toFake: ["setTimeout"] });
		try {
			const r = await refresher(4);
			r.advance(2100);
			await r.stores.lockStore.hold("g", "another", 60_000);
			const askedForLock = vi.spyOn(r.stores.lockStore, "hold");
			const waiting = r.call();
			await vi.waitFor(() => expect(askedForLock).toHaveBeenCalled());
			await vi.advanceTimersByTimeAsync(5000);
			expect(said(await waiting)).toBe("handed up-1");
			const later = r.call();
			await vi.advanceTimersByTimeAsync(1000);
			await letGo(r.stores.lockStore);
			await vi.advanceTimersByTimeAsync(100);
			expect(said(await later)).toBe("handed up-2");
			expect(r.asked.length).toBe(1);
		} finally {
			vi.useRealTimers();
		}
	});

	it("gives up on a lock another holder keeps once the held token cannot serve", async () => {
		vi.useFakeTimers({ toFake: ["setTimeout"] });
		try {
			const r = await refresher(4);
			r.advance(4100);
			await r.stores.lockStore.hold("g", "another", 60_000);
			const waiting = r.call();
			await vi.advanceTimersByTimeAsync(5100);
			expect(said(await waiting)).toBe("lock_timeout");
			expect(r.asked).toEqual([]);
		} finally {
			vi.useRealTimers();
		}
	});

	it("refuses a second refresh while one holds the lock", async () => {
		vi.useFakeTimers({ toFake: ["setTimeout"] });
		try {
			const r = await refresher(4);
			r.advance(4100);
			const late: { answer?: (refreshed: UpstreamRefresh) => void } = {};
			r.upstream.push(() => new Promise((resolve) => Object.assign(late, { answer: resolve })));
			const first = r.call();
			await vi.waitFor(() => expect(r.asked.length).toBe(1));
			expect(await r.stores.lockStore.hold("g", "another", 60_000)).toBe("exists");
			const second = r.call();
			await vi.advanceTimersByTimeAsync(5100);
			expect(said(await second)).toBe("lock_timeout");
			late.answer?.({
				kind: "refreshed",
				tokens: upstreamTokens({ accessToken: "up-2" }) as never,
			});
			expect(said(await first)).toBe("handed up-2");
			expect(r.asked.length).toBe(1);
		} finally {
			vi.useRealTimers();
		}
	});

	it("lets go of its lock once it has refreshed", async () => {
		const r = await refresher(4);
		r.advance(2100);
		r.upstream.push(async () => {
			expect(await r.stores.lockStore.hold("g", "another", 60_000)).toBe("exists");
			return { kind: "refreshed", tokens: upstreamTokens({ accessToken: "up-2" }) as never };
		});
		expect(said(await r.call())).toBe("handed up-2");
		// A lock let go ends a millisecond later.
		await new Promise((resolve) => setTimeout(resolve, 5));
		expect(await r.stores.lockStore.hold("g", "another", 60_000)).toBe("created");
	});

	it("lets go of its lock only while it still holds it, never one another holder took after it ran out", async () => {
		const r = await refresher(4);
		r.advance(2100);
		r.upstream.push(async () => {
			expect(await r.stores.lockStore.hold("g", "another", 60_000)).toBe("exists");
			// The upstream answers late: the lock runs out, and another holder takes it.
			r.advance(10_000);
			expect(await r.stores.lockStore.hold("g", "another", 60_000)).toBe("created");
			return { kind: "refreshed", tokens: upstreamTokens({ accessToken: "up-2" }) as never };
		});
		expect(said(await r.call())).toBe("handed up-2");
		await new Promise((resolve) => setTimeout(resolve, 5));
		expect(await r.stores.lockStore.hold("g", "third", 60_000)).toBe("exists");
	});

	it("reads the grant again under the lock: refreshed, revoked or unreadable meanwhile", async () => {
		const r = await refresher(4);
		r.advance(2100);
		r.upstream.push({
			kind: "refreshed",
			tokens: upstreamTokens({ accessToken: "narrow", scope: ["openid"] }) as never,
		});
		const all = await Promise.all([r.call(), r.call(), r.call({ scope: ["read"] })]);
		expect(all.map(said)).toEqual(["handed narrow", "handed narrow", "scope"]);
		expect(r.asked.length).toBe(1);
		for (const [meanwhile, answer] of [
			["revoked", "gone"],
			["unreadable", "reauthorize credentials_unreadable"],
		] as const) {
			const r = await refresher(4);
			r.advance(2100);
			await r.stores.lockStore.hold("g", "another", 60_000);
			const waiting = r.call();
			// Long enough for the request to wait on the lock.
			await new Promise((resolve) => setTimeout(resolve, 50));
			await r.stores.grants.change("g", (g) => ({
				value: (meanwhile === "revoked"
					? { ...g, status: "revoked" }
					: { ...g, sealed: "[]" }) as never,
			}));
			await letGo(r.stores.lockStore);
			expect(said(await waiting), meanwhile).toBe(answer);
		}
	});

	it("hands nothing another holder refreshed while it waited, once the subject is revoked or the grant ended", async () => {
		for (const meanwhile of ["grant ended", "subject revoked"] as const) {
			const r = await refresher(4);
			r.advance(2100);
			await r.stores.lockStore.hold("g", "another", 60_000);
			const waiting = r.call();
			// Long enough for the request to wait on the lock.
			await new Promise((resolve) => setTimeout(resolve, 50));
			// The other holder refreshes, so the token read under the lock is not due.
			const read = (await r.stored()) as Grant;
			const at = read.createdAt + 2100;
			const fresh = r.records.seal(read, {
				accessToken: "up-other",
				tokenType: "Bearer",
				refreshToken: "up-refresh-2",
				expiresAt: at + 300_000,
				obtainedAt: at,
				scope: shown,
			});
			await r.stores.grants.change("g", (g) => ({ value: { ...g, sealed: fresh } as never }));
			if (meanwhile === "subject revoked") r.boundary.revoked = true;
			else r.boundary.endsAt = 0;
			await letGo(r.stores.lockStore);
			expect(said(await waiting), meanwhile).toBe("gone");
			expect(r.asked, meanwhile).toEqual([]);
		}
	});
});

describe("a grant revoked while its upstream is asked", () => {
	it.each([
		["unavailable", () => Promise.reject(new Unavailable("test upstream"))],
		["refused", () => Promise.reject(new UpstreamRefused())],
		["limited", () => Promise.resolve({ kind: "limited" } as UpstreamRefresh)],
	] as const)("hands out no held token when the upstream then answers %s", async (_, answers) => {
		const r = await refresher(60);
		r.advance(31_000);
		r.upstream.push(async () => {
			// Revoked meanwhile, as a client's revoke or a subject's revocation writes it.
			await r.stores.grants.change("g", (record) => {
				const grant = r.records.grantOf(record) as Grant;
				return { value: r.records.stored({ ...withoutCredentials(grant), status: "revoked" }) };
			});
			return answers();
		});
		expect(said(await r.call())).toBe("gone");
	});
});

describe("a grant whose subject is revoked while its upstream is asked, the grant itself left active", () => {
	// As one its subject's listing missed: the follower never writes it, and only the boundary ends it.
	it.each([
		["unavailable", () => Promise.reject(new Unavailable("test upstream"))],
		["refreshed", () => Promise.resolve(undefined as unknown as UpstreamRefresh)],
	] as const)(
		"hands out nothing and writes nothing when the upstream then answers %s",
		async (_, answers) => {
			const r = await refresher(60);
			r.advance(31_000);
			const before = (await r.stored())?.sealed;
			r.upstream.push(async () => {
				r.boundary.revoked = true;
				const answered = await answers();
				return answered ?? { kind: "refreshed", tokens: upstreamTokens({ accessToken: "up-new" }) };
			});
			expect(said(await r.call())).toBe("gone");
			expect((await r.stored())?.sealed).toBe(before);
		},
	);
});

describe("a grant that ends while its upstream is asked, its status left as it was", () => {
	// lapse keeps the status to answer it, so only the end tells the grant is over.
	it.each([
		["unavailable", () => Promise.reject(new Unavailable("test upstream"))],
		["refreshed", () => Promise.resolve(undefined as unknown as UpstreamRefresh)],
	] as const)(
		"hands out nothing and writes nothing when the upstream then answers %s",
		async (_, answers) => {
			const r = await refresher(60);
			r.advance(31_000);
			const before = (await r.stored())?.sealed;
			r.upstream.push(async () => {
				r.boundary.endsAt = 0;
				const answered = await answers();
				return answered ?? { kind: "refreshed", tokens: upstreamTokens({ accessToken: "up-new" }) };
			});
			expect(said(await r.call())).toBe("gone");
			expect((await r.stored())?.sealed).toBe(before);
		},
	);
});
