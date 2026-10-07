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
 * The contract suite of core's `loginEntry` slot.
 * `loginEntryContract(input)` holds `urlFor` to the protocol `/authorize`
 * and the federation-grants connect flow send a browser by: `redirect_to`
 * added once to the page's own query, before any fragment (which is kept),
 * the target encoded whole so its query and fragment never read as the
 * page's; a page whose query already carries `redirect_to` is refused when
 * the entry is built. Core's `createTestLoginEntry` keeps it.
 */

import assert from "node:assert/strict";
import type { LoginEntry } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
import { unfrozenPath } from "../unfrozenPath.mjs";
import { CONTRACT_ORIGIN } from "./fakeHttp.mjs";

export interface LoginEntryContractInput {
	/** An entry for the login page `url`, as the provider builds one from a configuration naming that page. */
	readonly build: (url: string) => LoginEntry;
}

/** The parameter a login page reads where to come back to from. */
const RETURN_PARAMETER = "redirect_to";

const PAGES: readonly string[] = ["/login", "/login?tenant=acme", `${CONTRACT_ORIGIN}/sign-in`];

/** Pages with a fragment of their own — one with a `?` inside the fragment alone. */
const FRAGMENT_PAGES: readonly string[] = [
	"/login#x",
	"/login?tenant=acme#y",
	`${CONTRACT_ORIGIN}/sign-in#a?b`,
];

/** Pages whose own query already carries `redirect_to`, as written or percent-encoded, with a value or none. */
const CARRYING_PAGES: readonly string[] = [
	"/login?redirect_to=https://x",
	`${CONTRACT_ORIGIN}/sign-in?tenant=acme&redirect_to`,
	"/login?redirect%5Fto=x#y",
];

/** `url` split at its first `#`: the page before it, and the fragment with its `#`. */
const splitFragment = (url: string): readonly [string, string] => {
	const at = url.indexOf("#");
	return at === -1 ? [url, ""] : [url.slice(0, at), url.slice(at)];
};

const TARGETS: readonly string[] = [
	`${CONTRACT_ORIGIN}/oauth/authorize?client_id=a&tenant=evil&scope=openid%20profile&state=x`,
	"/federation-grants/connect?handle=abc",
	`${CONTRACT_ORIGIN}/consent?challenge=a#tenant=evil`,
	`${CONTRACT_ORIGIN}/ü?x=a b&redirect_to=https://attacker.test`,
];

const parse = (url: string): URL => new URL(url, CONTRACT_ORIGIN);

/** The cases of the `loginEntry` contract over the entries `input` builds. */
export function loginEntryContract(input: LoginEntryContractInput): readonly ContractCase[] {
	const { build } = input;
	return [
		{
			name: "url is the login page it was built for",
			run: async () => {
				for (const page of PAGES) {
					assert.equal(build(page).url, page, `an entry built for ${page} answers another url`);
				}
			},
		},
		{
			name: "urlFor adds redirect_to naming the target, once and whole",
			run: async () => {
				for (const page of PAGES) {
					const entry = build(page);
					for (const target of TARGETS) {
						const sent = entry.urlFor(target);
						assert.deepEqual(
							parse(sent).searchParams.getAll(RETURN_PARAMETER),
							[target],
							`${sent} does not name ${target} as redirect_to, once and whole`,
						);
					}
				}
			},
		},
		{
			name: "urlFor keeps the page: its path and its own query, with nothing of the target read as either",
			run: async () => {
				for (const page of PAGES) {
					const entry = build(page);
					const own = parse(page);
					for (const target of TARGETS) {
						const sent = entry.urlFor(target);
						const read = parse(sent);
						assert.ok(sent.startsWith(page), `${sent} does not keep the page ${page} as written`);
						assert.equal(read.origin, own.origin, `${sent} leaves the page's origin`);
						assert.equal(read.pathname, own.pathname, `${sent} is not the page's path`);
						assert.equal(read.hash, "", `${sent} reads part of the target as a fragment`);
						const names = new Set(
							[...read.searchParams.keys()].filter((k) => k !== RETURN_PARAMETER),
						);
						assert.deepEqual(
							[...names].sort(),
							[...new Set(own.searchParams.keys())].sort(),
							`${sent} carries a parameter the page does not`,
						);
						for (const name of names) {
							assert.deepEqual(
								read.searchParams.getAll(name),
								own.searchParams.getAll(name),
								`${sent} changes the page's ${name}`,
							);
						}
					}
				}
			},
		},
		{
			name: "urlFor adds redirect_to to a page's query before its fragment, and keeps the fragment",
			run: async () => {
				for (const page of FRAGMENT_PAGES) {
					const entry = build(page);
					const [before, fragment] = splitFragment(page);
					const own = parse(before);
					for (const target of TARGETS) {
						const sent = entry.urlFor(target);
						const [sentPage, sentFragment] = splitFragment(sent);
						assert.equal(
							sentFragment,
							fragment,
							`${sent} does not keep the page's fragment ${fragment}`,
						);
						assert.ok(
							sentPage.startsWith(before),
							`${sent} does not keep the page ${before} as written`,
						);
						const read = parse(sentPage);
						assert.deepEqual(
							read.searchParams.getAll(RETURN_PARAMETER),
							[target],
							`${sent} does not name ${target} as redirect_to in the page's query, once and whole`,
						);
						for (const name of new Set(own.searchParams.keys())) {
							assert.deepEqual(
								read.searchParams.getAll(name),
								own.searchParams.getAll(name),
								`${sent} changes the page's ${name}`,
							);
						}
					}
				}
			},
		},
		{
			name: "a page whose own query already carries redirect_to is refused when the entry is built",
			run: async () => {
				for (const page of CARRYING_PAGES) {
					assert.throws(
						() => build(page),
						`an entry was built for ${page}, whose query already carries redirect_to: the page would receive two`,
					);
				}
			},
		},
		{
			name: "the login entry is frozen",
			run: async () => {
				const found = unfrozenPath(build(PAGES[0] as string), "the entry");
				assert.equal(
					found,
					undefined,
					`${found} is not frozen: a module that reads the entry could change it under the others`,
				);
			},
		},
	];
}
