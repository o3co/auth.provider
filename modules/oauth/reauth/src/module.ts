import { defineModule } from "@mod/kernel";
import { reauths } from "./contract.ts";
import { reauthsOver } from "./reauths.ts";

export default defineModule({ name: "reauth" }, (m) => [m.provide(reauths).by(reauthsOver)]);
