import { Unavailable } from "@mod/kernel";
import type { Guarantee, Honours, Space } from "@mod/store";
import { type Redis, ReplyError } from "ioredis";
import { goodReplicaProblems } from "../probe/probe.ts";

/** The server's settings as the operator may declare them (`redis.server-settings`). */
export interface Declared {
	readonly "maxmemory-policy"?: string | undefined;
	readonly appendonly?: "yes" | "no" | undefined;
	readonly appendfsync?: "always" | "everysec" | "no" | undefined;
	readonly "no-appendfsync-on-rewrite"?: "yes" | "no" | undefined;
	readonly "min-replicas-to-write"?: number | undefined;
	readonly "min-replicas-max-lag"?: number | undefined;
}
export type SettingName = keyof Declared;

/** Whether the server refuses a command for good, for want of permission or of the command; any other error is no answer. */
export const refusedForGood = (error: unknown) =>
	error instanceof ReplyError &&
	/^(NOPERM|ERR unknown (sub)?command)\b/i.test((error as Error).message);

/** Reads a server setting by CONFIG GET; where the server refuses it or shows nothing, the operator's declaration. */
export type Settings = (name: SettingName) => Promise<string | undefined>;

/**
 * The server's settings: CONFIG GET where it answers, a declared value that differs then refused;
 * the declaration where the server refuses CONFIG or its answer is empty, which shows nothing to
 * compare, a setting left undeclared then refused.
 */
export function serverSettings(client: Redis, declared: Declared) {
	const problems: string[] = [];
	const used = new Set<SettingName>();
	const declaredOf = (name: SettingName) =>
		declared[name] === undefined ? undefined : String(declared[name]);
	const taken = (name: SettingName, why: string) => {
		used.add(name);
		const value = declaredOf(name);
		if (value === undefined) problems.push(`${why}: declare ${name} in redis.server-settings`);
		return value;
	};
	const read: Settings = async (name) => {
		let answered: string | undefined;
		try {
			answered = ((await client.config("GET", name)) as string[])[1];
		} catch (error) {
			if (!refusedForGood(error)) throw error;
			return taken(name, "the server refuses CONFIG GET");
		}
		if (answered === undefined) return taken(name, "the server's CONFIG GET does not show it");
		const value = declaredOf(name);
		if (value !== undefined && value !== answered) {
			problems.push(`redis.server-settings.${name} differs from what the server answers`);
		}
		return answered;
	};
	/** Compares every declared setting the checks did not read, so none is left unchecked where it can be. */
	const rest = async () => {
		for (const name of Object.keys(declared) as SettingName[]) await read(name);
	};
	return { read, rest, problems, used };
}

export type Role = [string, number, unknown[]];
export const roleOf = async (client: Redis) => (await client.call("ROLE")) as Role;
export const replicasOf = (role: Role) => (Array.isArray(role[2]) ? role[2].length : 0);

export async function evictionProblems(
	settings: Settings,
	declared: readonly Space[],
): Promise<string[]> {
	const kept = declared.filter((s) => s.guarantees.includes("no-eviction"));
	if (kept.length === 0 || (await settings("maxmemory-policy")) === "noeviction") return [];
	const names = kept.map((s) => s.name).join(", ");
	return [`the no eviction guarantee needs maxmemory-policy noeviction: ${names}`];
}

export async function replicationProblems(
	settings: Settings,
	role: Role,
	declared: readonly Space[],
	replication: "none" | "replicas" | undefined,
): Promise<string[]> {
	const replicated = declared.filter(
		(s) => s.guarantees.includes("replicated") || s.guarantees.includes("confirmed-reads"),
	);
	if (replicated.length === 0) return [];
	if (replication === undefined) {
		const names = replicated.map((s) => s.name).join(", ");
		return [
			`spaces need replicated or confirmed reads, so redis.replication (none or replicas) is required: ${names}`,
		];
	}
	if (
		replication === "replicas" &&
		(Number(await settings("min-replicas-to-write")) < 1 ||
			Number(await settings("min-replicas-max-lag")) < 1)
	) {
		return [
			"with replication replicas, set min-replicas-to-write and min-replicas-max-lag to 1 or more",
		];
	}
	if (replication === "none" && replicasOf(role) > 0) {
		return ["replication is none but a replica is connected"];
	}
	return [];
}

export async function durabilityProblems(
	settings: Settings,
	declared: readonly Space[],
	durability: "none" | undefined,
): Promise<string[]> {
	const durable = declared.filter((s) => s.guarantees.includes("durable"));
	if (durable.length === 0 || durability === "none") return [];
	// Each is read, so a refusal names every setting left undeclared at once. A rewrite that skips
	// its fsyncs loses an acknowledged write in a crash, as appendfsync other than always does.
	const [appendonly, appendfsync, onRewrite] = [
		await settings("appendonly"),
		await settings("appendfsync"),
		await settings("no-appendfsync-on-rewrite"),
	];
	const persisted = appendonly === "yes" && appendfsync === "always" && onRewrite === "no";
	if (persisted) return [];
	const names = durable.map((s) => s.name).join(", ");
	return [
		`set appendonly yes, appendfsync always and no-appendfsync-on-rewrite no on the server (docs/runbook.md, Redis), which the durable guarantee of these spaces needs: ${names}`,
	];
}

/**
 * Whether the server gives these guarantees now, read as boot reads them, with replicas from ROLE
 * and good replicas as the probe counts them; settings taken as declared make it declared.
 */
export async function honoursOf(
	client: Redis,
	s: {
		readonly durability?: "none" | undefined;
		readonly replication?: "none" | "replicas" | undefined;
		readonly "server-settings"?: Declared | undefined;
	},
	wanted: readonly Guarantee[],
): Promise<Honours> {
	try {
		const asked: Space[] = wanted.length > 0 ? [{ name: "asked", guarantees: wanted }] : [];
		const replicated = wanted.includes("replicated") || wanted.includes("confirmed-reads");
		const reasons: string[] = [];
		if (s.durability === "none" && wanted.includes("durable")) {
			reasons.push("redis.durability is none: a crash loses the latest writes");
		}
		if (s.replication === "none" && replicated) {
			reasons.push("redis.replication is none: a failover loses writes");
		}
		const role = await roleOf(client);
		const settings = serverSettings(client, s["server-settings"] ?? {});
		reasons.push(
			...(await evictionProblems(settings.read, asked)),
			...(await replicationProblems(settings.read, role, asked, s.replication)),
			...(await durabilityProblems(settings.read, asked, s.durability)),
		);
		if (s.replication === "replicas" && replicated) {
			if (replicasOf(role) === 0) reasons.push("no replica is connected");
			const needed = await settings.read("min-replicas-to-write");
			const info = await client.info("replication");
			reasons.push(...goodReplicaProblems(info, needed === undefined ? undefined : Number(needed)));
		}
		reasons.push(...settings.problems);
		if (reasons.length > 0) return { kind: "unmet", reasons };
		return settings.used.size > 0
			? { kind: "declared", settings: [...settings.used] }
			: { kind: "verified" };
	} catch {
		throw new Unavailable("store");
	}
}
