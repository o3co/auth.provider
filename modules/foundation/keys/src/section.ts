import { jwksSettings } from "./jwks/jwks.ts";
import { sectionWith } from "./signing/section.ts";

/** The operator section: the ring's keys (`signing`), and how long the published set is cached (`jwks`). */
export const section = sectionWith(jwksSettings);
