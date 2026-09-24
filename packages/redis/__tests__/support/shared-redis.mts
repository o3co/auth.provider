/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * What `redis-container.global.mts` hands every test file in this package:
 * where the one Redis container of the run listens, or why there is none.
 *
 * Types only, shared by the global setup that provides the value and the
 * helper that injects it (`redis.mts`), so the two cannot disagree about it.
 */
export type SharedRedis =
	| { readonly host: string; readonly port: number; readonly databases: number }
	| { readonly unavailable: string };

declare module "vitest" {
	export interface ProvidedContext {
		readonly sharedRedis: SharedRedis;
	}
}
