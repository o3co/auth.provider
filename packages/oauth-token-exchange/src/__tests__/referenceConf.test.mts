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
 * The package's `config/reference.conf`: the module that reads it declares
 * it as its section's reference, and it holds only that section, which the
 * section's schema parses without losing a path — core's
 * `packageReferenceProblems`, the check every package with defaults runs over
 * its own file — with `maxActorChainDepth` at 3 unless
 * `OAUTH_TOKEN_EXCHANGE_MAX_ACTOR_CHAIN_DEPTH` says otherwise. The section
 * refuses an unknown key at every level (core's `sectionStrictnessProblems`).
 */

import {
	packageReferenceProblems,
	sectionStrictnessProblems,
} from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { tokenExchangeModule } from "#/module.mjs";

/** The package's defaults, as a composition root finds them. */
const REFERENCE = new URL("../../config/reference.conf", import.meta.url);

const read =
	(env: Record<string, string> = {}) =>
	(path: string): unknown =>
		parseFile(path, { env }).toObject();

describe("the package's config/reference.conf", () => {
	const modules = [tokenExchangeModule];

	it("is read at the section named after its module", () => {
		expect(
			modules.map((module) => [module.name, module.section !== undefined, module.section?.at]),
		).toEqual([["oauth-token-exchange", true, undefined]]);
	});

	it("is declared by the module and holds only its section, which its schema parses without losing a path", () => {
		expect(packageReferenceProblems({ reference: REFERENCE, modules, read: read() })).toEqual([]);
	});

	it("holds a section that refuses an unknown key at every level", () => {
		const path = new URL(REFERENCE).pathname;
		expect(sectionStrictnessProblems(modules, { tree: read()(path) })).toEqual([]);
	});

	it("defaults maxActorChainDepth to 3, and reads OAUTH_TOKEN_EXCHANGE_MAX_ACTOR_CHAIN_DEPTH", () => {
		const path = new URL(REFERENCE).pathname;
		expect(read()(path)).toEqual({ "oauth-token-exchange": { maxActorChainDepth: 3 } });
		expect(read({ OAUTH_TOKEN_EXCHANGE_MAX_ACTOR_CHAIN_DEPTH: "5" })(path)).toEqual({
			"oauth-token-exchange": { maxActorChainDepth: "5" },
		});
	});
});
