import { area } from "@mod/conformance";

export interface RecipesPart {
	/** The modules the recipe's generate command composes, as the app it generates depends on them. */
	readonly modules: readonly string[];
	/** The `config/local.conf` the recipe's reader writes, as written: the app boots that file, and the recipe shows it. */
	readonly localConf?: string;
}

export const recipesArea = area<RecipesPart>("recipes");
