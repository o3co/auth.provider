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
 * boot/csrf-guard-slot.mts: what boot does for the `csrfGuard` slot.
 * Whatever fills it — a host's bootstrap or override value, or a provider's
 * — enters the component map as a frozen snapshot of the guard, each member
 * read once, with `middleware` held to being a request handler and `check`
 * to being a function. So every reader of the slot mounts or asks the guard
 * that was checked, and none checks it again.
 */

import type { CsrfGuard } from "../browser-session/types.mjs";
import { describeValue } from "../errors/describe-value.mjs";
import type { ComponentKey } from "../modules/manifest/component-map.mjs";

/** What stage 3 does to the `csrfGuard` slot. */
export interface CsrfGuardSlot {
	/** Before any provider runs: replaces a host's value in the slot with its snapshot. */
	beforeProviders(): void;
	/** The value the working map holds for a provider's `value` under `key`. */
	provided(key: ComponentKey, value: unknown): unknown;
}

const INSTALL =
	"Install the session module's guard (sessionModule), or one that keeps core's CsrfGuard contract.";

const refuse = (member: string, rule: string): never => {
	throw new RangeError(`csrfGuard.${member} ${rule}. ${INSTALL}`);
};

/** A member of the guard, read once; a read that throws is refused, naming the member. */
const readOnce = (member: string, read: () => unknown): unknown => {
	try {
		return read();
	} catch (cause) {
		throw new RangeError(`csrfGuard.${member} could not be read. ${INSTALL}`, { cause });
	}
};

/**
 * `value` as the slot holds it: a frozen snapshot of the guard, each member
 * read once. `middleware` must be a function of at most three parameters —
 * Express takes one of four or more for an error handler and skips it — and
 * `check` a function. The other members are carried as read. A method is
 * bound to the guard it was read from, so a guard written as a class
 * answers through the snapshot as it would itself.
 *
 * @throws RangeError naming the member that breaks the contract or whose
 *   read throws (the read's error as its `cause`), or the slot when it holds
 *   no guard object.
 */
function snapshotOf(value: unknown): CsrfGuard {
	if ((typeof value !== "object" && typeof value !== "function") || value === null) {
		throw new RangeError(
			`csrfGuard must be the guard object its contract describes, and the composition's slot holds ${describeValue(value)}. ${INSTALL}`,
		);
	}
	const guard = value as Record<string, unknown>;
	const member = (name: string): unknown => readOnce(name, () => guard[name]);
	const method = (name: string): unknown => {
		const read = member(name);
		return typeof read === "function" ? read.bind(guard) : read;
	};

	const middleware = member("middleware");
	const arity =
		typeof middleware === "function" ? readOnce("middleware", () => middleware.length) : undefined;
	if (typeof arity !== "number" || arity > 3) {
		const held =
			typeof middleware !== "function"
				? describeValue(middleware)
				: typeof arity === "number"
					? `a function of ${arity} parameters`
					: `a function whose length is ${describeValue(arity)}`;
		refuse(
			"middleware",
			`is not a request handler: the routes it guards mount it in front of themselves, so it must be a function of at most three parameters, and the composition's slot holds ${held}`,
		);
	}
	const check = method("check");
	if (typeof check !== "function") {
		refuse(
			"check",
			`is not a function: the routes that answer a refusal in their own vocabulary ask it, and the composition's slot holds ${describeValue(check)}`,
		);
	}
	const bodyField = member("bodyField");
	return Object.freeze({
		cookieName: member("cookieName"),
		headerName: member("headerName"),
		...(bodyField === undefined ? {} : { bodyField }),
		check,
		checkNavigation: method("checkNavigation"),
		middleware,
		issue: method("issue"),
	}) as CsrfGuard;
}

/**
 * Stage 3's handling of the `csrfGuard` slot in `components`, the working
 * map.
 *
 * - A host's value is replaced before any provider runs; one that breaks
 *   the contract is refused with the check's RangeError, naming the member.
 * - A provider's value is replaced as it is materialised; its refusal is the
 *   caller's to report, after its rollback, as a failed provider. A cleanup
 *   is still handed the provider's own value.
 * - An empty key stays empty, as `undefined` does: a slot left unfilled is
 *   stage 3's to judge against what requires it.
 */
export function csrfGuardSlotFor(components: Record<string, unknown>): CsrfGuardSlot {
	return {
		beforeProviders() {
			if (!Object.hasOwn(components, "csrfGuard") || components.csrfGuard === undefined) return;
			components.csrfGuard = snapshotOf(components.csrfGuard);
		},
		provided(key, value) {
			return key === "csrfGuard" && value !== undefined ? snapshotOf(value) : value;
		},
	};
}
