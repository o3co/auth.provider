import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { createMemoryReplaySeenSet } from "./adapters/memory.mjs";
export function createReplaySeenSetFactory() {
    return createAdapterFactory("ReplaySeenSet");
}
export function registerBuiltinReplaySeenSets(factory) {
    factory.register("memory", () => createMemoryReplaySeenSet());
}
