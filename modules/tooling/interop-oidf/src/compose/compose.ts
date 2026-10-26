import { createHash } from "node:crypto";
import { ownerLabel } from "../orphans/orphans.ts";

/** The name the suite's server reaches this machine by, and the IPv4 address it is given where Docker gives it none. */
export interface ComposedHost {
	readonly name: string;
	readonly mapped?: string;
}

/**
 * The compose file beside the suite's own: its store is in memory, never a directory of this
 * machine's (a run's store is thrown away, and Docker Desktop's shared directories can refuse its
 * writes); its server reaches this machine by name, mapped to an IPv4 address alone (`host-gateway`
 * adds an IPv6 one the suite's Java may pick and find no route to); every container is labelled with
 * the process that owns it; its nginx answers with the harness's certificate, which names the
 * suite's host, so a client checking names can reach it.
 */
export const composeOverride = (
	host: ComposedHost,
	tls: { readonly cert: string; readonly key: string },
	owner: number = process.pid,
) => {
	const labels = `    labels:\n      ${ownerLabel}: "${owner}"\n`;
	return `services:
  mongodb:
    volumes:
      - type: tmpfs
        target: /data/db
${labels}  nginx:
    volumes:
      - type: bind
        source: ${tls.cert}
        target: /etc/ssl/certs/nginx-selfsigned.crt
        read_only: true
      - type: bind
        source: ${tls.key}
        target: /etc/ssl/private/nginx-selfsigned.key
        read_only: true
${labels}  server:
${host.mapped === undefined ? "" : `    extra_hosts:\n      - "${host.name}:${host.mapped}"\n`}${labels}`;
};

/**
 * The compose file's environment: the image tag pinned, and the suite's public origins as the
 * harness names them, never as the runner's environment has them (vitest sets `BASE_URL` to `/`
 * for Vite, which the compose file would take for the suite's origin).
 */
export const suiteEnv = (
	tag: string,
	origins: { readonly base: string; readonly mtls: string },
): NodeJS.ProcessEnv => ({
	...process.env,
	IMAGE_TAG: tag,
	BASE_URL: origins.base,
	BASE_MTLS_URL: origins.mtls,
});

/** A start's Compose project: one of its own, from its whole directory, as every start's ends alike. */
export const projectOf = (dir: string) =>
	`o3co-oidf-${createHash("sha256").update(dir).digest("hex").slice(0, 16)}`;
