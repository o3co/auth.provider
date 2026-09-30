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
 * The declared-absence vocabulary for optional DI slots.
 *
 * An `optional` key alone reads as "absence means nothing to do", which lets a
 * capability look wired when it is not (revocation with no denylist, a
 * watermark nothing consults, an audit sink that discards every event). A
 * module attaches an {@link AbsencePolicy} to an optional key, and boot's
 * stage-1 guard (`checkDeclaredAbsence`) refuses to start with
 * `component-absence-undeclared` unless the slot is filled or config declares
 * the capability absent (e.g. `oauth.revocation.accessToken = "unsupported"`).
 *
 * The policy is **data, not code** (a config path and the one value that counts
 * as the declaration), so stage 1 stays deterministic and side-effect-free and
 * the boot error can name the exact line to write. A policy that needs to
 * compute absence means the declaration vocabulary is wrong, not that this
 * type needs a callback. {@link isAbsenceDeclared} is the one reading of a
 * declaration, and {@link describeAbsenceDeclaration} the one way of saying how
 * to write it.
 */
export interface AbsencePolicy {
	/**
	 * Path into the parsed application config, one segment per element
	 * (`["oauth", "revocation", "subject"]` reads
	 * `config.oauth.revocation.subject`), where an operator declares the
	 * capability absent on purpose.
	 */
	readonly configKey: readonly string[];
	/**
	 * The one value at {@link configKey} that counts as the declaration,
	 * compared with `===`; where the key holds a list (core's
	 * `core.declaredAbsent`), a member of it. A declaration that needs
	 * coercion should point at a schema-validated key instead.
	 */
	readonly absentValue: string;
	/**
	 * Operator-facing sentence appended to the boot error: what the slot does,
	 * so an operator choosing between wiring it and declaring it absent knows
	 * what the deployment loses.
	 */
	readonly hint: string;
}

/** Core's own list of the slots a composition runs without on purpose. */
const DECLARED_ABSENT = ["core", "declaredAbsent"] as const;

/** Whether `configKey` is core's list of declared absences. */
const isDeclaredAbsentList = (configKey: readonly string[]): boolean =>
	configKey.length === DECLARED_ABSENT.length &&
	configKey.every((segment, index) => segment === DECLARED_ABSENT[index]);

/**
 * Whether `config` declares `policy`'s capability absent: the value at its
 * `configKey`, read as own properties (a key an object inherits is not one
 * anyone wrote), is its `absentValue` — or, at core's own list,
 * `core.declaredAbsent`, a list holding it.
 */
export function isAbsenceDeclared(config: unknown, policy: AbsencePolicy): boolean {
	let value: unknown = config;
	for (const segment of policy.configKey) {
		if (value === null || typeof value !== "object" || !Object.hasOwn(value, segment)) {
			return false;
		}
		value = (value as Record<string, unknown>)[segment];
	}
	return isDeclaredAbsentList(policy.configKey) && Array.isArray(value)
		? value.includes(policy.absentValue)
		: value === policy.absentValue;
}

/**
 * How an operator declares `policy`'s capability absent, as a clause:
 * `list "auditSink" in core.declaredAbsent` for core's list,
 * `set oauth.revocation.subject = "unsupported"` for any other key.
 */
export function describeAbsenceDeclaration(policy: AbsencePolicy): string {
	const key = policy.configKey.join(".");
	return isDeclaredAbsentList(policy.configKey)
		? `list "${policy.absentValue}" in ${key}`
		: `set ${key} = "${policy.absentValue}"`;
}
