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
 * `oauth-token-exchange.maxActorChainDepth` is read as a whole number in
 * decimal digits: a typo such as `"1e3"` or `"0x10"`, or an
 * exported-but-empty variable, fails boot naming the key instead of being
 * read as some other number.
 */

import { describe, expect, it } from "vitest";
import { tokenExchangeModule } from "#/module.mjs";

const parse = (maxActorChainDepth: unknown) => {
	const schema = tokenExchangeModule.section?.schema;
	if (schema === undefined) throw new Error("the module declares no section");
	return schema.safeParse({ maxActorChainDepth });
};

const issuesAtKey = (result: ReturnType<typeof parse>) =>
	(result.error?.issues ?? [])
		.filter((issue) => issue.path.map(String).join(".") === "maxActorChainDepth")
		.map((issue) => issue.message);

const MESSAGE = "must be a whole number of at least 1, in decimal digits";

describe("oauth-token-exchange.maxActorChainDepth is read in decimal digits", () => {
	it.each([
		["0x10"],
		["1e3"],
		["5.0"],
		["+5"],
		[true],
		[""],
		["  "],
		["Infinity"],
		["NaN"],
		[Number.POSITIVE_INFINITY],
		[Number.NaN],
	])("refuses %j, naming the key", (value) => {
		const result = parse(value);
		expect(result.success).toBe(false);
		expect(issuesAtKey(result)).toEqual([MESSAGE]);
	});

	it.each([[0], ["0"]])("refuses %j, below the minimum", (value) => {
		expect(issuesAtKey(parse(value))).toEqual([MESSAGE]);
	});

	it.each([[60], ["60"], [" 60 "]])("reads %j as 60", (value) => {
		const result = parse(value);
		expect(result.error?.issues ?? []).toEqual([]);
		expect(result.data).toEqual({ maxActorChainDepth: 60 });
	});
});
