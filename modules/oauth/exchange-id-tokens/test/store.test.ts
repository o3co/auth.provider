import { usedIdTokensContract } from "../src/testing.ts";
import { memoryUsedIdTokens } from "./stores.ts";

usedIdTokensContract("records stand-in", async () => memoryUsedIdTokens());
