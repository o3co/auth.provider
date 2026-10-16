import { metadataSections } from "@mod/clients";
import { defineModule } from "@mod/kernel";
import { allowances } from "./metadata.ts";

export default defineModule({ name: "client-allowance", replicaSafe: true }, (m) => [
	m.contribute(metadataSections).by(() => allowances),
]);
