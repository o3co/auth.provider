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
// (comma-separated) unresolvable, as they are in a deployment that did not
// install them. The hook stubs nothing and throws nothing of its own: it hands
// a hidden package's specifier back to Node's own resolver, asked from the
// filesystem root, where no `node_modules` holds it, so what the process sees
// is the resolver's real `ERR_MODULE_NOT_FOUND`.
import { registerHooks } from "node:module";

const hidden = new Set((process.env.HIDE_PACKAGES ?? "").split(",").filter(Boolean));
const NOWHERE = "file:///";

const packageName = (specifier) =>
	specifier.startsWith("@")
		? specifier.split("/").slice(0, 2).join("/")
		: (specifier.split("/")[0] ?? specifier);

registerHooks({
	resolve(specifier, context, nextResolve) {
		if (hidden.has(packageName(specifier))) {
			return nextResolve(specifier, { ...context, parentURL: NOWHERE });
		}
		return nextResolve(specifier, context);
	},
});
