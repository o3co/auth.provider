/** Tools for the area modules' scenes. */

export { hostLibfaketime } from "./clock/clock.ts";
export {
	type Deployment,
	type DeploymentRecord,
	type DeploymentSpec,
	type Instance,
	startDeployment,
} from "./deployment/deployment.ts";
export type { Traced } from "./deployment/trace.ts";
export { faultRun, faultRunReporter } from "./fault-run.ts";
export {
	type Deployed,
	type Deploying,
	deployed,
	failover,
	instanceOf,
	on,
	ready,
	reconnected,
	recovered,
	replicasOnline,
	repointed,
	successes,
	writable,
} from "./fault-scene/fault-scene.ts";
export {
	type Node,
	redisImage,
	startTopology,
	type Topology,
	type TopologySpec,
} from "./faults/topology.ts";
export type {
	Command,
	Connection,
	Drop,
	Dropped,
	Execution,
	Held,
	Match,
	Relay,
	Reply,
	Role,
} from "./relay/relay.ts";
export { type FakeSmtp, fakeSmtp } from "./smtp.ts";
export {
	confirmation,
	isNoReplicas,
	isOutOfMemory,
	keysOf,
	type Operation,
	roleOf,
	runIdOf,
	type StoreKey,
	type StoreWrite,
	sameMark,
	storeRead,
	storeWrite,
	writtenValues,
} from "./store-wire/store-wire.ts";
