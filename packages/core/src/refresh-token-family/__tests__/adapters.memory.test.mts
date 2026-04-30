/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { createMemoryRefreshTokenFamilyStore } from "../adapters/memory.mjs";
import { runRefreshTokenFamilyStoreContract } from "./adapters.contract.mjs";

runRefreshTokenFamilyStoreContract(async () => createMemoryRefreshTokenFamilyStore());
