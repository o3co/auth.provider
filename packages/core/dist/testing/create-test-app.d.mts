import { type AppHandle, type BootstrapMap, type CreateAppOptions, type DefaultBootstrapMap } from "../boot/index.mjs";
import type { TestInspect } from "./test-inspect.mjs";
export type { TestInspect } from "./test-inspect.mjs";
export type TestAppHandle = AppHandle & {
    readonly inspect: TestInspect;
};
/**
 * `createTestApp` extends the Phase 4 boot planner's `createApp` with:
 * 1. Synthesised bootstrap components when `bootstrapComponents` is omitted —
 *    a minimal `{ config, pathResolver }` sufficient for a smoke-test boot.
 *    When `bootstrapComponents` is supplied, it is used verbatim — NO MERGE.
 * 2. A read-only `inspect` view of registries (grants, federations,
 *    tokenExchangeValidators, routes), exposed on the returned handle.
 *
 * Per A2-γ §7.2: TestInspect is a testing-only escape hatch and MUST NOT
 * appear on the production AppHandle.
 */
export declare function createTestApp<B extends BootstrapMap = DefaultBootstrapMap>(options?: Partial<CreateAppOptions<B>>): Promise<TestAppHandle>;
//# sourceMappingURL=create-test-app.d.mts.map