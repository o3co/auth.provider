/** For the migration tests: spaces with their index spaces on one simulated store, and what they read and write. */
import { createHash } from "node:crypto";
import type { Walk } from "@mod/erasure-extensions";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Json, type Key, type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { indexSpaceOf } from "../src/subject-records.ts";

const held = contract<Store>("test.placed-store");

/** A subject's index partition in a space, as `index` names it. */
export const part = (space: Space, subject: string) =>
	`1.${createHash("sha256").update(`${space.name}\n${subject}`).digest("base64url")}`;
/** The bucket a key's entry is listed in. */
export const bucketOf = (key: string) => `m${createHash("sha256").update(key).digest("hex")[0]}`;
export const envelope = (subject: string, value: Json) => ({ "records:v": 1, subject, value });

/** The spaces given, each beside its index space, on a fresh simulated store. */
export async function placed(given: readonly Space[]) {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [
			simulated.module,
			defineModule({ name: "user", replicaSafe: false, takes: [store] }, (m) => [
				...given.flatMap((space) => [
					m.contribute(spaces).by(() => space),
					m.contribute(spaces).by(() => indexSpaceOf(space)),
				]),
				m.provide(held).by((c) => c.get(store)),
			]),
		],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const s = app.get(held);
	const random = {
		bytes: (n: number) => new Uint8Array(n).map(() => Math.floor(Math.random() * 256)),
	};
	/** A place in `space`, indexed unless said, with a cap and a clock for sets. */
	const at = (space: Space, phase: "reader" | "indexed" = "indexed", now = 0) => ({
		store: s,
		space,
		index: indexSpaceOf(space),
		random,
		phase,
		cap: 10,
		clock: { now: () => now },
	});
	/** A walk as the tool hands it in, every page on one server, each key `twice` where asked. */
	const walk = (twice = false): Walk => ({
		sweep: async (name, cursor) => {
			const space = given.find((one) => one.name === name) as Space;
			const page = await s.scan(space, cursor);
			const keys: readonly Key[] = twice ? page.keys.flatMap((k) => [k, k]) : page.keys;
			return page.cursor === undefined
				? { keys, server: "one" }
				: { keys, cursor: page.cursor, server: "one" };
		},
	});
	/** A raw value written before indexing, as a record (the default) or a set, endless unless `ms`. */
	const put = (space: Space, partition: string, value: Json, ms?: number, name = "record") =>
		s.putIfAbsent({ space, partition, name }, value, {
			expiry: ms === undefined ? { kind: "never" } : { kind: "after", ms },
		});
	const raw = async (space: Space, partition: string, name = "record") =>
		(await s.get({ space, partition, name })).entry;
	/** An entry of a subject's index: a bucket by its name, or its witness. */
	const index = async (space: Space, subject: string, name: string) =>
		(
			await s.get({
				space: indexSpaceOf(space),
				partition: `${part(space, subject)}.${name}`,
				name: "record",
			})
		).entry?.value;
	return { s, simulated, at, walk, put, raw, index };
}
