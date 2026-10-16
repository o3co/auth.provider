import { defineModule } from "@mod/kernel";
import { deciding } from "./deciding.ts";

/**
 * A stand-in for tests of routes that use the policy or the origin evidence. It decides as the
 * module does and serves no route; without a public origin it refuses every unsafe request.
 */
export const csrfStandIn = defineModule({ name: "csrf" }, (m) => deciding(m, "refuse requests"));
