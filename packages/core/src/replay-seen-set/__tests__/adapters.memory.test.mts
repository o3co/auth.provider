/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { createMemoryReplaySeenSet } from "../adapters/memory.mjs";
import { runReplaySeenSetContract } from "./adapters.contract.mjs";

runReplaySeenSetContract("memory", {
	create: () => createMemoryReplaySeenSet(),
});
