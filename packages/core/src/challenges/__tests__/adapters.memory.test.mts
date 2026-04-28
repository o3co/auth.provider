/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { createMemoryChallengeStore } from "../adapters/memory.mjs";
import { runChallengeStoreContract } from "./adapters.contract.mjs";

runChallengeStoreContract("memory", {
	create: () => createMemoryChallengeStore(),
});
