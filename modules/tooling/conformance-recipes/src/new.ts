import { randomBytes } from "node:crypto";
import { type NewPart, onNew } from "@mod/conformance";
import { type RecipesPart, recipesArea } from "./area.ts";

/** The recipe's own modules, on Redis, with a second factor required: what its reader configures. */
const setUp = (part: RecipesPart): NewPart => ({
	modules: [...part.modules],
	store: "pausable",
	config: {
		mfa: { mode: "required" },
		seal: { current: { id: "recipes", key: randomBytes(32).toString("base64") } },
	},
});

onNew(recipesArea, setUp);
