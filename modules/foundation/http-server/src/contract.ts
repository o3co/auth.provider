// The words the server reads and answers by: http's (its routes, requests and answers), and its own
// policies' rules and marks, which stand in place of any http still has. Its units read them here.
export * from "@mod/http";
export {
	applying,
	type Guarantee,
	type Mark,
	marks,
	type PolicyRule,
	policies,
} from "./policies.ts";
