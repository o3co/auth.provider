/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { describe } from "vitest";
import { createMemoryRefreshTokenFamilyStore } from "../adapters/memory.mjs";
import { runRefreshTokenFamilyStoreContract } from "./adapters.contract.mjs";

describe("the memory refresh-token family store", () => {
	runRefreshTokenFamilyStoreContract(async () => createMemoryRefreshTokenFamilyStore());
});
