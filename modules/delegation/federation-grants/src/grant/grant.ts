import type { Client, Section } from "@mod/clients";
import type { Log, Random } from "@mod/kernel";
import type { Seal } from "@mod/seal";
import type { BoundaryKind, Revocations } from "@mod/subject-revocation";
import type { Upstreams } from "@mod/upstreams";
import { z } from "zod";
import type { Connection, Settings } from "../section.ts";
import type { StoredGrant, StoredStep, SubjectGrants } from "../store.ts";

const scopes = z.array(z.string().min(1)).readonly();

const intentShape = z
	.strictObject({
		id: z.string().min(1),
		kind: z.enum(["initial", "reauthorization"]),
		returnUri: z.string().min(1),
		state: z.string(),
		scopes,
		lifetimeMs: z.number().int().positive(),
		expectedUpstream: z.string().min(1).optional(),
		startedAt: z.number().int(),
		endsAt: z.number().int(),
		/** Why it ended; none while it may still be connected. */
		ended: z.string().min(1).optional(),
		/** The session that took its question: the browser it is bound to. */
		session: z.string().min(1).optional(),
		/** The last step-up trip: the requirement it was for and when it was asked; `true`, as an earlier version wrote it, is a trip for no requirement at no time. */
		stepped: z
			.union([
				z.literal(true),
				z.strictObject({ requirement: z.string().min(1), at: z.number().int() }).readonly(),
			])
			.optional(),
	})
	.readonly();

const grantShape = z
	.strictObject({
		format: z.literal(1),
		id: z.string().min(1),
		client: z.string().min(1),
		subject: z.string().min(1),
		connection: z.string().min(1),
		status: z.enum([
			"pending",
			"active",
			"reauthorization_required",
			"upstream_token_ineligible",
			"revoked",
		]),
		reason: z.string().min(1).optional(),
		createdAt: z.number().int(),
		/** What the user was shown at the last activation; a refresh never narrows it. */
		scopes,
		authorizedAt: z.number().int().optional(),
		expiresAt: z.number().int().optional(),
		/** When its token was last handed out. */
		lastUsedAt: z.number().int().optional(),
		upstream: z.strictObject({ issuer: z.string(), subject: z.string() }).readonly().optional(),
		intent: intentShape.optional(),
		sealed: z.string().optional(),
		/** Changes with every write of the credentials, so a write lands only over what it read. */
		version: z.string().min(1),
		/** Upstream refreshes taken in the window that opened at `from`. */
		rotations: z.strictObject({ from: z.number().int(), count: z.number().int() }).readonly(),
	})
	.readonly();

const credentialsShape = z
	.strictObject({
		accessToken: z.string().min(1),
		tokenType: z.string(),
		refreshToken: z.string().min(1).optional(),
		expiresAt: z.number().int(),
		obtainedAt: z.number().int(),
		scope: scopes,
	})
	.readonly();

const stepShape = z
	.strictObject({
		format: z.literal(1),
		kind: z.enum(["link", "question", "upstream"]),
		grant: z.string().min(1),
		intent: z.string().min(1),
		session: z.string().min(1).optional(),
		verifier: z.string().min(1).optional(),
		nonce: z.string().min(1).optional(),
		connection: z.string().min(1).optional(),
		taken: z.boolean().optional(),
	})
	.readonly();

/** How long a grant's record stays after it can no longer be used, so status still answers. */
export const retentionMs = 30 * 86_400_000;

/** A secret from `random`: 32 bytes, base64url. */
export const secretFrom = (random: Random) => () =>
	Buffer.from(random.bytes(32)).toString("base64url");

/** The operator's connections by name, and those whose IdP offers a delegation now. */
export function connectionsIn(settings: Settings, upstreams: Upstreams) {
	const of = (name: string): Connection | undefined =>
		Object.hasOwn(settings.connections, name) ? settings.connections[name] : undefined;
	return {
		of,
		/** A configured connection and the delegation of its IdP; none when either is missing. */
		configured: (name: string) => {
			const connection = of(name);
			const delegation = connection && upstreams.of(connection.idp)?.delegation;
			return connection && delegation ? { connection, delegation } : undefined;
		},
	};
}

/** A return URI must not carry what the end of a connection adds. */
const reserved = (uri: string) => {
	const query = URL.parse(uri)?.searchParams;
	return query !== undefined && ["grant_id", "state", "error"].some((name) => query.has(name));
};

/** Client metadata: the connections a client may ask for, and where a browser may be sent back. */
export const clientSection: Section<{
	readonly connections: readonly string[];
	readonly "return-uris": readonly string[];
}> = {
	name: "federation-grants",
	schema: z.strictObject({
		connections: z.array(z.string().min(1)).prefault([]),
		"return-uris": z
			.array(
				z
					.url()
					.refine((uri) => !reserved(uri), "a return URI may not hold grant_id, state or error"),
			)
			.prefault([]),
	}),
};

/** Whether a client may ask for a connection: only one the operator registered, and only one listed. */
export const permits = (client: Client | undefined, connection: string) =>
	client?.registered === true &&
	client.kind === "confidential" &&
	client.section(clientSection).connections.includes(connection);

/** Whether a browser may be sent back to `uri`: only an exact match of the client's list. */
export const returnsTo = (client: Client | undefined, uri: string) =>
	client?.section(clientSection)["return-uris"].includes(uri) === true;

export type Grant = z.output<typeof grantShape>;
export type Intent = z.output<typeof intentShape>;
export type Credentials = z.output<typeof credentialsShape>;
export type Step = z.output<typeof stepShape>;

/** The grant without its sealed credentials, as it is kept once they may no longer be used. */
export const withoutCredentials = (grant: Grant): Grant => {
	const { sealed: _gone, ...rest } = grant;
	return rest;
};

/** The scope tokens of a space-delimited value (RFC 6749 §3.3); none when it holds anything else or nothing. */
export function scopeTokens(value: string): readonly string[] | undefined {
	if (!/^[\x21\x23-\x5b\x5d-\x7e]+( [\x21\x23-\x5b\x5d-\x7e]+)*$/.test(value)) return undefined;
	return [...new Set(value.split(" "))];
}

export const within = (asked: readonly string[], allowed: readonly string[]) =>
	asked.every((s) => allowed.includes(s));

/** Reads and writes grants and steps, and seals a grant's credentials bound to the grant. */
export function recordsWith(seal: Seal) {
	const contextOf = (grant: Grant) =>
		`federation-grants\n${grant.id}\n${grant.subject}\n${grant.client}\n${grant.connection}`;
	return {
		/** A record of another shape is no grant. */
		grantOf: (stored: StoredGrant | undefined): Grant | undefined => {
			const read = grantShape.safeParse(stored);
			return read.success ? read.data : undefined;
		},
		stored: (grant: Grant) => grantShape.parse(grant) as unknown as StoredGrant,
		stepOf: (stored: StoredStep | undefined): Step | undefined => {
			const read = stepShape.safeParse(stored);
			return read.success ? read.data : undefined;
		},
		storedStep: (step: Step) => stepShape.parse(step) as unknown as StoredStep,
		/** The credentials, or none when there are none, they do not open, or they open to another shape. */
		open: (grant: Grant): Credentials | undefined => {
			if (grant.sealed === undefined) return undefined;
			const opened = seal.open(grant.sealed, contextOf(grant));
			if (opened.kind !== "opened") return undefined;
			try {
				const read = credentialsShape.safeParse(JSON.parse(opened.plain));
				return read.success ? read.data : undefined;
			} catch {
				return undefined;
			}
		},
		resealed: (grant: Grant): Grant | undefined => {
			if (grant.sealed === undefined) return grant;
			const opened = seal.open(grant.sealed, contextOf(grant));
			if (opened.kind !== "opened") return undefined;
			return opened.stale ? { ...grant, sealed: seal.seal(opened.plain, contextOf(grant)) } : grant;
		},
		seal: (grant: Grant, credentials: Credentials) =>
			seal.seal(JSON.stringify(credentialsShape.parse(credentials)), contextOf(grant)),
	};
}

export type Records = ReturnType<typeof recordsWith>;

/** Lists a grant under its subject for a revocation's closing work; a failed write is logged and passed, as the boundary still refuses. */
export function listingWith(subjects: SubjectGrants, log: Log) {
	return async (grant: Grant, lifetimeMs: number) => {
		try {
			await subjects.add(grant.subject, grant.id, lifetimeMs);
		} catch (error) {
			const kind = error instanceof Error ? error.name : typeof error;
			log.warn("federation-grants.listing_failed", { kind });
		}
	};
}

export type Listing = ReturnType<typeof listingWith>;

/**
 * Judges a grant against its subject's revocation boundaries, each widened by the allowance for
 * hosts' clocks, and against its end.
 */
export function judgeWith(
	revocations: Revocations,
	{ keep, maxMs, allowanceMs }: { keep: boolean; maxMs: number; allowanceMs: number },
) {
	// Kept grants answer only to `delegations`; otherwise either boundary ends one.
	const kinds: readonly BoundaryKind[] = keep ? ["delegations"] : ["sessions", "delegations"];
	return {
		/** Whether a subject's revocation since its activation ends the grant. */
		revoked: async (grant: Grant): Promise<boolean> => {
			if (grant.authorizedAt === undefined) return false;
			for (const kind of kinds) {
				const at = await revocations.compare(grant.subject, grant.authorizedAt, kind, allowanceMs);
				if (at === "revoked") return true;
			}
			return false;
		},
		/** Whether an intent started before the subject's `sessions` boundary, which ends any intent. */
		intentRevoked: async (grant: Grant, intent: Intent) =>
			(await revocations.compare(grant.subject, intent.startedAt, "sessions", allowanceMs)) ===
			"revoked",
		/** When the grant ends, held to the longest a grant may live now. */
		endOf: (grant: Grant) =>
			grant.authorizedAt === undefined || grant.expiresAt === undefined
				? undefined
				: Math.min(grant.expiresAt, grant.authorizedAt + maxMs),
	};
}

export type Judge = ReturnType<typeof judgeWith>;

/** Why an upstream's tokens cannot be held, in the words a callback's answer uses. */
export type Ineligible = "refresh_token_absent" | "upstream_token_ineligible" | "scope_exceeded";

/** What an upstream's tokens say, each part read once; a part that cannot be read is none. */
function readOnce(tokens: unknown) {
	const part = (name: string): unknown => {
		try {
			return (tokens as Record<string, unknown>)[name];
		} catch {
			return undefined;
		}
	};
	const text = (value: unknown) => (typeof value === "string" && value !== "" ? value : undefined);
	const scope = part("scope");
	return Object.freeze({
		accessToken: text(part("accessToken")),
		tokenType: text(part("tokenType")),
		refreshToken: text(part("refreshToken")),
		expiresIn: part("expiresInSeconds"),
		scope:
			Array.isArray(scope) && scope.every((s) => typeof s === "string" && s !== "")
				? ([...scope] as readonly string[])
				: undefined,
	});
}

/**
 * The one judgment of upstream tokens and when they end, on `kernel`'s clock: a refresh token where
 * none is held yet, an access token whose finite life is within the connection's longest, a scope
 * within what the user was shown (none said is all of it), then a bearer type. The rotated refresh
 * token is answered whatever the rest says, so it is never lost.
 */
export function credentialsFrom(
	tokens: unknown,
	at: {
		readonly now: number;
		readonly maxAccessMs: number;
		readonly shown: readonly string[];
		readonly held?: string;
	},
):
	| { readonly kind: "held"; readonly credentials: Credentials }
	| { readonly kind: "refused"; readonly why: Ineligible; readonly refreshToken?: string } {
	const said = readOnce(tokens);
	const refreshToken = said.refreshToken ?? at.held;
	const refused = (why: Ineligible) =>
		({ kind: "refused", why, ...(refreshToken ? { refreshToken } : {}) }) as const;
	if (refreshToken === undefined) return refused("refresh_token_absent");
	const life = said.expiresIn;
	const finite = typeof life === "number" && Number.isFinite(life) && life > 0;
	if (!said.accessToken || !finite || life * 1000 > at.maxAccessMs) {
		return refused("upstream_token_ineligible");
	}
	const scope = said.scope === undefined || said.scope.length === 0 ? at.shown : said.scope;
	if (!within(scope, at.shown)) return refused("scope_exceeded");
	if (said.tokenType?.toLowerCase() !== "bearer") return refused("upstream_token_ineligible");
	return {
		kind: "held",
		credentials: {
			accessToken: said.accessToken,
			tokenType: said.tokenType,
			refreshToken,
			expiresAt: at.now + life * 1000,
			obtainedAt: at.now,
			scope,
		},
	};
}
