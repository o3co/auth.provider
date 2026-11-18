import { defineModule } from "@mod/kernel";

// Takes and offers nothing yet; it holds nothing, so it is safe on many instances.
export default defineModule({ name: "account-erasure", replicaSafe: true, takes: [] }, () => []);
