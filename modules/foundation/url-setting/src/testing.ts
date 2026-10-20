import { type ConfiguredUrl, urlSetting } from "./contract.ts";

/** A URL as url-setting would read it from a configuration, for a test; one url-setting would refuse throws. */
export const configuredUrl = (url: string): ConfiguredUrl =>
	urlSetting({ schemes: ["https", "http"] }).parse(url);
