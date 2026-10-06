/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * boot/host-maps.mts: the one boundary where boot reads a map a composition
 * root hands it — `bootstrapComponents`, `overrideComponents`,
 * `contributionKinds` — before anything else does. Its own keys are listed
 * once and each slot's own property is read once (a getter called once), so
 * a getter, a Proxy trap or an inherited property cannot answer one thing to
 * a check and another to a later stage. What it answers is a map without a
 * prototype whose slots are plain data properties; the host's map is never
 * changed. The configuration, `bootstrapComponents.config`, is also copied as
 * frozen plain data (`copyPlainJson`'s rule, `-0` read as `0` as JSON writes
 * it, since HOCON resolves it from what an operator wrote), so every check
 * and every later stage reads that copy alone. A component is kept as the
 * value read: it is an object or a function boot hands on.
 *
 * A listing or a read that throws refuses boot under the reason the slot's own
 * check uses, never with what it threw: `config-validation-failed` for the
 * map and `config`, `config-defaults-invalid` for `configDefaults`, and
 * `missing-required-component` for a component slot, which then supplies
 * nothing boot could hand on. A configuration that is no object (a string) is
 * kept for the composed parse to refuse. A function is read as a map, like
 * any object; a map that is neither is handed on as it is, for stage 1 to
 * judge.
 */

import type { z } from "zod";
import { copyPlainJsonNegativeZeroAsZero } from "../json/plainJson.mjs";
import type { ComponentKey } from "../modules/manifest/component-map.mjs";
import { BootError } from "./types.mjs";

/** The host maps boot reads, by the name a refusal gives them. */
export type HostMapName = "bootstrapComponents" | "overrideComponents" | "contributionKinds";

/** The maps this boundary answered: handed to it again, they are answered as they are. */
const snapshots = new WeakSet<object>();

/** The refusal of a configuration that cannot be read or copied: one issue at its root. */
function configRefused(message: string): BootError {
	const issues = [{ code: "custom", path: [], message } as z.ZodIssue];
	return new BootError({
		message: `Config validation failed — 1 issue(s) found: (the configuration): ${message}.`,
		reason: "config-validation-failed",
		stage: "validateManifests",
		details: { reason: "config-validation-failed", issues, modules: [] },
	});
}

const THREW = "reading it threw";

/** The refusal of a slot named `key` of map `name` whose read threw. */
function slotRefused(name: HostMapName, key: string): BootError {
	if (name === "bootstrapComponents" && key === "config") {
		return configRefused(`the configuration could not be read: ${THREW}`);
	}
	if (name === "bootstrapComponents" && key === "configDefaults") {
		return new BootError({
			message: `bootstrapComponents.configDefaults could not be read: ${THREW}. Hand boot the configuration's defaults as plain data.`,
			reason: "config-defaults-invalid",
			stage: "validateManifests",
			details: { reason: "config-defaults-invalid", path: [], problem: THREW },
		});
	}
	return new BootError({
		message: `${name}.${key} could not be read: ${THREW}, so the slot supplies nothing boot can hand on. Hand boot the component itself, as a data property.`,
		reason: "missing-required-component",
		stage: "validateManifests",
		details: {
			reason: "missing-required-component",
			missingKey: key as ComponentKey,
			rootModule: `<${name}>`,
			path: [],
		},
	});
}

/** Whether `key` of map `name` is an input boot reads by its name rather than a component it lists. */
const readByName = (name: HostMapName, key: string): boolean =>
	name === "bootstrapComponents" && (key === "config" || key === "configDefaults");

/** `bootstrapComponents.config` as the copy every later stage reads. */
function copiedConfig(handed: unknown): unknown {
	if (handed === null || typeof handed !== "object") return handed;
	const taken = copyPlainJsonNegativeZeroAsZero(handed);
	if (taken.ok) return taken.copy;
	const where = taken.at === "" ? "the configuration" : `the configuration at ${taken.at}`;
	throw configRefused(
		`${where} is not plain data: a read threw there, or it holds a value configuration cannot (a getter or Proxy that throws, a class instance, a symbol's field, a cycle)`,
	);
}

/**
 * `map` as boot reads it (see this file's header): its own string keys listed
 * once, each slot's own property read once — an own enumerable one, and
 * `bootstrapComponents.config` and `configDefaults` whether or not
 * enumerable — into a map without a prototype;
 * `bootstrapComponents.config` copied as frozen plain data. An own
 * `__proto__` is kept as a key holding `undefined`, its value never read:
 * stage 1 refuses it whatever it holds. A map this function answered is
 * answered as it is.
 */
export function snapshotHostMap<T>(map: T, name: HostMapName): T {
	// A function carrying slots is read as a map too, so no map escapes the
	// boundary by being callable.
	if (map === null || (typeof map !== "object" && typeof map !== "function")) return map;
	if (snapshots.has(map)) return map;
	let keys: readonly PropertyKey[];
	try {
		keys = Reflect.ownKeys(map);
	} catch {
		throw configRefused(`${name} could not be read: listing its keys threw`);
	}
	const snapshot: Record<string, unknown> = Object.create(null);
	for (const key of keys) {
		if (typeof key !== "string") continue;
		let value: unknown;
		if (key !== "__proto__") {
			try {
				const descriptor = Reflect.getOwnPropertyDescriptor(map, key);
				// A key the listing named and the map no longer holds: none. A
				// component slot is an own enumerable key, as boot reads the maps;
				// the inputs boot reads by name count whether or not enumerable.
				if (descriptor === undefined) continue;
				if (!descriptor.enumerable && !readByName(name, key)) continue;
				value = "value" in descriptor ? descriptor.value : descriptor.get?.call(map);
			} catch {
				throw slotRefused(name, key);
			}
		}
		Object.defineProperty(snapshot, key, {
			value: name === "bootstrapComponents" && key === "config" ? copiedConfig(value) : value,
			enumerable: true,
			writable: true,
			configurable: true,
		});
	}
	snapshots.add(snapshot);
	return snapshot as T;
}
