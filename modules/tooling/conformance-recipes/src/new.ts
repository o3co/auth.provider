import { randomBytes } from "node:crypto";
import { type NewPart, onNew } from "@mod/conformance";
import { type RecipesPart, recipesArea } from "./area.ts";

/**
 * The recipe's own modules, set up as its command composes them: on Redis where it composes Redis,
 * with a second factor required where it composes `mfa`, and a seal key where it composes `seal`;
 * the file its reader writes boots below those.
 */
export const setUp = (part: RecipesPart): NewPart => {
	const composes = (name: string) => part.modules.includes(name);
	return {
		modules: [...part.modules],
		store: composes("@mod/redis") ? "pausable" : "volatile",
		config: {
			...(composes("@mod/mfa") ? { mfa: { mode: "required" } } : {}),
			...(composes("@mod/seal")
				? { seal: { current: { id: "recipes", key: randomBytes(32).toString("base64") } } }
				: {}),
		},
		...(part.localConf === undefined ? {} : { layer: part.localConf }),
	};
};

onNew(recipesArea, setUp);
