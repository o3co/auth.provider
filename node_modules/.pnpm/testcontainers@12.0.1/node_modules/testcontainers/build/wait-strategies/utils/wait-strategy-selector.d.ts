import { ContainerInspectInfo } from "dockerode";
import { ContainerRuntimeClient } from "../../container-runtime";
import { HealthCheck } from "../../types";
import { WaitStrategy } from "../wait-strategy";
type WaitStrategySelectorOptions = {
    client: ContainerRuntimeClient;
    inspectResult: ContainerInspectInfo;
    waitStrategy?: WaitStrategy;
    healthCheck?: HealthCheck;
    imageNames?: string[];
};
export declare const selectWaitStrategy: ({ client, inspectResult, waitStrategy, healthCheck, imageNames, }: WaitStrategySelectorOptions) => Promise<WaitStrategy>;
export {};
