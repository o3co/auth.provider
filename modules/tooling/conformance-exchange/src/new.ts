import { type NewPart, onNew } from "@mod/conformance";
import { type ExchangePart, exchangeArea } from "./area.ts";

const setUp = (part: ExchangePart): NewPart => ({
	modules: ["@mod/token-exchange"],
	store: "volatile",
	config: {
		"token-exchange": {
			...(part.maxActorDepth ? { "max-actor-depth": part.maxActorDepth } : {}),
			...(part.maxLifetimeSeconds ? { "max-lifetime": `${part.maxLifetimeSeconds}s` } : {}),
		},
	},
});

const unvouched =
	"a grant without a session on an app with a user ledger and verified-email: no source can vouch for the subject's email";

onNew(exchangeArea, setUp, (part, _, modules) =>
	part.sessionless && ["@mod/users-http", "@mod/verified-email"].every((m) => modules.includes(m))
		? { leaveOut: unvouched }
		: setUp(part),
);
