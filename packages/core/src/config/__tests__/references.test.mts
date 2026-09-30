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
 * `moduleReferences`: the `reference.conf` files the loaded modules
 * declare (`section.reference`), deduplicated, in module order, with core's
 * own at the bottom — the chain a composition root layers beneath its own
 * files. And `referenceConfProblems`, on core's testing entry: the check a
 * package runs over its own `config/reference.conf` — the file holds only
 * its modules' sections, and each section's schema keeps every path it has.
 */

import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { coreReference, moduleReferences } from "#/config/references.mjs";
import { defineModule } from "#/modules/manifest/index.mjs";
import type { Module } from "#/modules/manifest/module-spec.mjs";
import { packageReferenceProblems, referenceConfProblems } from "#/testing/referenceConf.mjs";

const REF_A = new URL("file:///packages/a/config/reference.conf");
const REF_B = new URL("file:///packages/b/config/reference.conf");
/** Core's own `reference.conf`, found from this file. */
const CORE_HREF = new URL("../../../config/reference.conf", import.meta.url).href;

const sectioned = (name: string, reference: URL | undefined, at?: string): Module =>
	defineModule({
		name,
		section: {
			schema: z.unknown(),
			...(reference === undefined ? {} : { reference }),
			...(at === undefined ? {} : { at }),
		},
	});

describe("moduleReferences — the references a composition layers beneath its own files", () => {
	it("names core's own reference.conf, a file that exists", () => {
		expect(coreReference().href).toBe(CORE_HREF);
		expect(existsSync(fileURLToPath(coreReference()))).toBe(true);
	});

	it("answers a new URL for core's each time, so changing one changes no other", () => {
		const first = coreReference();
		first.pathname = "/elsewhere/reference.conf";
		expect(coreReference().href).toBe(CORE_HREF);
	});

	it("hands out copies: changing an answer changes neither a module's declaration nor the next answer", () => {
		const declared = new URL(REF_A.href);
		const module = sectioned("a", declared);
		const [first, core] = moduleReferences([module]);
		(first as URL).pathname = "/elsewhere/reference.conf";
		(core as URL).pathname = "/elsewhere/core.conf";
		expect(declared.href).toBe(REF_A.href);
		expect(moduleReferences([module]).map(String)).toEqual([REF_A.href, CORE_HREF]);
	});

	it("answers core's alone for modules that declare none", () => {
		expect(
			moduleReferences([defineModule({ name: "plain" }), sectioned("no-reference", undefined)]).map(
				String,
			),
		).toEqual([CORE_HREF]);
	});

	it("answers each declared reference once, in module order, with core's at the bottom", () => {
		const references = moduleReferences([
			sectioned("b-one", REF_B),
			sectioned("a-one", REF_A),
			sectioned("b-two", new URL(REF_B.href)),
			defineModule({ name: "plain" }),
		]);
		expect(references.map(String)).toEqual([REF_B.href, REF_A.href, CORE_HREF]);
	});

	it("keeps core's at the bottom when a module declares it too", () => {
		expect(
			moduleReferences([sectioned("declares-core", new URL(CORE_HREF)), sectioned("a", REF_A)]).map(
				String,
			),
		).toEqual([REF_A.href, CORE_HREF]);
	});

	it("refuses a reference that is not a file: URL, naming the module", () => {
		const forged = {
			name: "forged",
			section: { schema: z.unknown(), reference: "file:///x/reference.conf" },
		} as unknown as Module;
		expect(() => moduleReferences([forged])).toThrow(
			/module "forged": section\.reference must be a file: URL/,
		);
		expect(() =>
			moduleReferences([sectioned("remote", new URL("https://example.test/reference.conf"))]),
		).toThrow(/module "remote": section\.reference must be a file: URL/);
	});
});

describe("referenceConfProblems — a package's reference holds its modules' sections, whole", () => {
	const dpopLike = defineModule({
		name: "dpop-like",
		section: {
			schema: z.object({ enabled: z.boolean(), window: z.number().default(60) }),
			reference: REF_A,
			at: "oauth.dpop",
		},
	});

	it("finds nothing wrong with a reference its modules' sections parse whole", () => {
		expect(
			referenceConfProblems({
				tree: { oauth: { dpop: { enabled: false, window: 30 } } },
				reference: REF_A,
				modules: [dpopLike],
			}),
		).toEqual([]);
	});

	it("names a path no module that declares the reference owns", () => {
		expect(
			referenceConfProblems({
				tree: { oauth: { dpop: { enabled: false }, mtls: { enabled: false } }, extra: 1 },
				reference: REF_A,
				modules: [dpopLike],
			}),
		).toEqual([
			"extra: no module declaring this reference owns it",
			"oauth.mtls.enabled: no module declaring this reference owns it",
		]);
	});

	it("names a path a section's schema loses, and a value it refuses", () => {
		expect(
			referenceConfProblems({
				tree: { oauth: { dpop: { enabled: false, forgotten: "x" } } },
				reference: REF_A,
				modules: [dpopLike],
			}),
		).toEqual(['oauth.dpop.forgotten: lost by module "dpop-like"\'s section schema']);
		expect(
			referenceConfProblems({
				tree: { oauth: { dpop: { enabled: "no" } } },
				reference: REF_A,
				modules: [dpopLike],
			}),
		).toEqual([
			expect.stringMatching(
				/^oauth\.dpop\.enabled: refused by module "dpop-like"'s section schema/,
			),
		]);
	});

	it("counts no key whose value is undefined as a path", () => {
		expect(
			referenceConfProblems({
				tree: { oauth: { dpop: { enabled: false, retired: undefined } }, stray: undefined },
				reference: REF_A,
				modules: [dpopLike],
			}),
		).toEqual([]);
	});

	it("counts an empty object as kept when the schema's output has keys under it", () => {
		const filling = defineModule({
			name: "filling",
			section: {
				schema: z.object({
					enabled: z.boolean(),
					limits: z.object({ token: z.number().default(60) }),
				}),
				reference: REF_A,
				at: "oauth.dpop",
			},
		});
		expect(
			referenceConfProblems({
				tree: { oauth: { dpop: { enabled: false, limits: {} } } },
				reference: REF_A,
				modules: [filling],
			}),
		).toEqual([]);
		// An empty object the schema drops is still lost.
		expect(
			referenceConfProblems({
				tree: { oauth: { dpop: { enabled: false, limits: {} } } },
				reference: REF_A,
				modules: [dpopLike],
			}),
		).toEqual(['oauth.dpop.limits: lost by module "dpop-like"\'s section schema']);
	});

	it("names a reference no module declares", () => {
		expect(referenceConfProblems({ tree: {}, reference: REF_B, modules: [dpopLike] })).toEqual([
			`${REF_B.href}: no module declares this reference`,
		]);
	});

	it("reads the sections of every module declaring the reference, a nested one included", () => {
		const outer = sectioned("outer", REF_B, "outer-section");
		const inner = sectioned("inner", REF_B, "outer-section.factors.inner");
		expect(
			referenceConfProblems({
				tree: {
					"outer-section": { lockout: { threshold: 5 }, factors: { inner: { enabled: true } } },
				},
				reference: REF_B,
				modules: [outer, inner, dpopLike],
			}),
		).toEqual([]);
	});
});

describe("packageReferenceProblems — the check each package's test runs over its own reference", () => {
	const dpopLike = defineModule({
		name: "dpop-like",
		section: { schema: z.object({ enabled: z.boolean() }), reference: REF_A, at: "oauth.dpop" },
	});

	it("reads the file with the reader it is given, and checks what it read", () => {
		const read = vi.fn((_path: string): unknown => ({ oauth: { dpop: { enabled: false } } }));
		expect(packageReferenceProblems({ reference: REF_A, modules: [dpopLike], read })).toEqual([]);
		expect(read).toHaveBeenCalledWith(fileURLToPath(REF_A), {});

		const lossy = vi.fn((_path: string): unknown => ({
			oauth: { dpop: { enabled: false, x: 1 } },
		}));
		expect(
			packageReferenceProblems({ reference: REF_A, modules: [dpopLike], read: lossy }),
		).toEqual(['oauth.dpop.x: lost by module "dpop-like"\'s section schema']);
	});

	it("names each module it is given that does not declare the file", () => {
		const read = (): unknown => ({ oauth: { dpop: { enabled: false } } });
		expect(
			packageReferenceProblems({
				reference: REF_A,
				modules: [dpopLike, sectioned("elsewhere", REF_B), defineModule({ name: "plain" })],
				read,
			}),
		).toEqual([
			`module "elsewhere": its section's reference is ${REF_B.href}, not this file`,
			'module "plain": declares no section reference',
		]);
	});
});
