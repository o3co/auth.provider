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
// (comma-separated) unresolvable, to `import` and to `require` alike, as they
// are in a deployment that did not install them. The hook stubs nothing and
// throws nothing of its own: a hidden package is looked up by Node's own
// resolver from the filesystem root, where no `node_modules` holds it, so the
// process sees that resolver's real error — `ERR_MODULE_NOT_FOUND` for an
// import, `MODULE_NOT_FOUND` for a require.
//
// The two need different means. For an import, the hook hands the specifier
// back with the root as `parentURL`. Node's CommonJS resolution searches from
// the requiring module whatever `parentURL` says, so for a require (the
// `require` condition) the hook asks a `require` created at the root instead,
// which throws — provided NODE_PATH is unset: CommonJS resolution searches it
// from anywhere, and pnpm sets it for the scripts it runs, so the test starts
// this process without it.
//
// `module.registerHooks` needs Node >= 22.15 or >= 23.5; the test that loads
// this file checks for it first.
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
