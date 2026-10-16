import type { Pattern } from "./pattern.ts";
import { simpleWeb } from "./simple-web.ts";

export const nativeApp: Pattern = {
	name: "native-app",
	use:
		"A login for native and single-page apps: public clients use the authorization code flow " +
		"with PKCE and refresh, and may bind their tokens to a key they hold (DPoP). It needs no " +
		"outside system.",
	axes: simpleWeb.axes,
	features: { ...simpleWeb.features, binding: ["@mod/dpop"] },
	areas: ["keys", "identity", "code", "oauth", "ops"],
	conformanceAdd: [],
};
