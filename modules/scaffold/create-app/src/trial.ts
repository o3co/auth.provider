/** Trial settings for a generated app, kept until its callers take `trial`'s layer. */
import { trialLayer } from "@mod/trial";

/**
 * The trial layer for the app generated in `target`, the given settings written as its caller's
 * layer; the environment is empty. Kept until its callers take `trialLayer`.
 */
export async function trialSettings(
	target: string,
	settings: {
		readonly redisUrl: string;
		readonly port?: number;
		readonly deployment?: "single" | "multi";
		readonly leave?: readonly string[];
		/** Hosts the caller's own layer needs reached, merged into the trial's one outbound list. */
		readonly allow?: readonly string[];
		readonly plainLoopback?: readonly string[];
		/** Clients the caller's own layer registers, merged into the trial's one `clients.registered`. */
		readonly clients?: readonly unknown[];
	},
): Promise<{ readonly env: Record<string, string>; readonly local: string }> {
	const json = JSON.stringify;
	const layer = [
		...(settings.deployment ? [`kernel.deployment = ${settings.deployment}`] : []),
		...(settings.port ? [`http.port = ${settings.port}`] : []),
		...(settings.allow ?? []).map((host) => `outbound.allow += ${json(host)}`),
		...(settings.plainLoopback ?? []).map((host) => `outbound.plain-loopback += ${json(host)}`),
		...(settings.clients ?? []).map((client) => `clients.registered += ${json(client)}`),
	].join("\n");
	const local = await trialLayer(target, {
		redisUrl: settings.redisUrl,
		...(settings.leave ? { leave: settings.leave } : {}),
		layer,
	});
	return { env: {}, local };
}
