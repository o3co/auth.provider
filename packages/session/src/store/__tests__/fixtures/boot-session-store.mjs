/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

// Boots `sessionStoreModuleFor(config)` through core's `createApp`, the way a
// composition root does, with `session.storage.type` set from
// SESSION_STORAGE_TYPE, and prints the outcome as the last line of stdout:
// `RESULT {"booted":true}` or `RESULT {"booted":false,"message":"…"}`.
//
// It imports this package by its own name, which resolves through `exports`
// to the built `dist` — the files a consumer installs — because the point is
// what Node's resolver does with them: run it after `pnpm run build`.
import { createApp } from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { sessionStoreModuleFor } from "@o3co/auth-provider-session";

const type = process.env.SESSION_STORAGE_TYPE ?? "memory";
const base = makeValidAppConfig();
const config = {
	...base,
	session: {
		...base.session,
		// A port nothing listens on: the builder never gets as far as
		// connecting when a package it loads is missing.
		storage: { type, redis: { url: "redis://127.0.0.1:1" } },
	},
};

const report = (outcome) => console.log(`RESULT ${JSON.stringify(outcome)}`);

try {
	const handle = await createApp({
		modules: [sessionStoreModuleFor(config)],
		bootstrapComponents: { config, pathResolver: (s) => s },
	});
	await handle.dispose();
	report({ booted: true });
} catch (err) {
	report({ booted: false, message: err instanceof Error ? err.message : String(err) });
}
