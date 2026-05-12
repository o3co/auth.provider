/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { createMemoryAccessTokenDenylist } from "../memory.mjs";
import { runAccessTokenDenylistContract } from "./adapters.contract.mjs";

runAccessTokenDenylistContract("memory", {
	create: () => createMemoryAccessTokenDenylist(),
});
