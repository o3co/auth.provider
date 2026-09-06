/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
/**
 * Structural type guard for the {@link SupportsLock} capability.
 *
 * Returns `false` for `null` / `undefined` so consumers can call this directly on
 * results without an explicit existence check. When `store` is non-null, returns
 * `true` when `store.acquireLock` is a function. Inside a `true` branch, TypeScript
 * narrows `store` to `FederationTokenStoreBase & SupportsLock`, so
 * `store.acquireLock(...)` is callable without a cast.
 */
export function supportsLock(store) {
    if (store == null)
        return false;
    return typeof store.acquireLock === "function";
}
