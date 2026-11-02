import { clientSources } from "@mod/clients";
import { metadata } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { section } from "./section.ts";
import { sourceOver, sourceTakes, supportedOver } from "./source.ts";

export default defineModule(
	{ name: "clients-cimd", section, replicaSafe: true, takes: sourceTakes },
	(m) => [
		// Without the code grant composed, no document client could do anything.
		m.contribute(metadata).by(async (c) => ({
			name: "client_id_metadata_document_supported",
			value: await supportedOver(c),
		})),
		m.contribute(clientSources).by(sourceOver),
	],
);
