/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

// Loaded with `node --import`: makes the packages named in HIDE_PACKAGES
// (comma-separated) unresolvable to `import` and `require` alike, as in a
// deployment that did not install them. The hook stubs and throws nothing of
// its own: a hidden package is looked up by Node's resolver from the
// filesystem root, so the process sees that resolver's real error —
// `ERR_MODULE_NOT_FOUND` for an import, `MODULE_NOT_FOUND` for a require.
//
// An import is handed back with the root as `parentURL`. CommonJS resolution
// searches from the requiring module whatever `parentURL` says, so a require
// (the `require` condition) asks a `require` created at the root instead.
// That needs NODE_PATH unset — CommonJS searches it from anywhere, and pnpm
// sets it — so the test starts this process without it. CommonJS's global
// folders (`~/.node_modules`, `~/.node_libraries`, `$PREFIX/lib/node`) are
// searched from anywhere too: a package installed there is not hidden from
// `require`, and the test's require probe fails on such a machine.
//
// `module.registerHooks` needs Node >= 22.15 or >= 23.5; on an older Node the
// test that loads this file skips the cases that would, and on CI asserts the
// API is there.
import { createRequire, registerHooks } from "node:module";

const hidden = new Set((process.env.HIDE_PACKAGES ?? "").split(",").filter(Boolean));
const NOWHERE = "file:///";
const requireFromNowhere = createRequire(NOWHERE);

const packageName = (specifier) =>
	specifier.startsWith("@")
		? specifier.split("/").slice(0, 2).join("/")
		: (specifier.split("/")[0] ?? specifier);

// `requireFromNowhere.resolve` runs this hook again; that lookup is the one
// that must reach Node's resolver untouched.
let resolvingFromNowhere = false;

registerHooks({
	resolve(specifier, context, nextResolve) {
		if (resolvingFromNowhere || !hidden.has(packageName(specifier))) {
			return nextResolve(specifier, context);
		}
		if (context.conditions?.includes("require")) {
			resolvingFromNowhere = true;
			try {
				requireFromNowhere.resolve(specifier);
			} finally {
				resolvingFromNowhere = false;
			}
		}
		return nextResolve(specifier, { ...context, parentURL: NOWHERE });
	},
});
