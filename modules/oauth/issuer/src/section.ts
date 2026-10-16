import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export const section = z.strictObject({
	url: urlSetting({ schemes: ["https", "http"], trailingSlash: "refused", query: false }).describe(
		"The issuer the tokens name, as clients see it; no query and no trailing slash.",
	),
});
