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
 * A relocation's tombstone held to the one case it is for. A tombstone is an
 * old path's `${?VARIABLE}` binding a `reference.conf` keeps, with no
 * default, after the path moved, so a variable an operator still exports is
 * refused (`config-path-relocated`) rather than ignored. It is only for a
 * variable whose name changed with the path: one the new path is bound to
 * (e.g. a Redis store's `…_KEY_PREFIX`) was set correctly, and a tombstone
 * would refuse it.
 */

import assert from "node:assert/strict";
import { environmentVariableFor } from "../config/environment-variable.mjs";

/** A tombstone: the variable an old path stays bound to, and the dot path the key moved to. */
export interface RelocationTombstone {
	readonly variable: string;
	readonly to: string;
}

/** Throws when `tombstone.variable` is the variable `tombstone.to` is bound to. */
export function assertRelocationTombstone(tombstone: RelocationTombstone): void {
	const bound = environmentVariableFor(tombstone.to.split("."));
	assert.notEqual(
		tombstone.variable,
		bound,
		`${tombstone.variable} is the variable ${tombstone.to} is bound to: a tombstone for it would refuse the operator who set it for the new path — keep a tombstone only for a variable whose name changed`,
	);
}
