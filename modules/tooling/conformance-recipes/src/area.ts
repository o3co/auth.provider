import { area } from "@mod/conformance";

export interface RecipesPart {
	/** The modules the recipe's generate command composes, as the app it generates depends on them. */
	readonly modules: readonly string[];
}

export const recipesArea = area<RecipesPart>("recipes");
