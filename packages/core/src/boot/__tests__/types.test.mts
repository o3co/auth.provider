/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { describe, expect, expectTypeOf, it } from 'vitest';
import type { AppConfig } from '../../config/application.schema.mjs';
import type { PathResolver } from '../../modules/types.mjs';
import type {
  AppHandle,
  BootErrorDetails,
  BootErrorReason,
  BootStage,
  BootstrapComponentCollisionDetails,
  CircularDependencyDetails,
  ConfigValidationFailedDetails,
  ContributeAndOverrideSameKeyDetails,
  ContributeFactoryFailedDetails,
  DefaultBootstrapMap,
  DuplicateContributeDetails,
  DuplicateModuleNameDetails,
  DuplicateOverrideDetails,
  DuplicateProvidesDetails,
  InvalidRouteAdvertisementPathDetails,
  LifecycleWithoutProvidesDetails,
  ListShapedOverrideDetails,
  MissingRequiredComponentDetails,
  OverrideTargetMissingDetails,
  ProvidesFactoryFailedDetails,
  RouteOrderCycleDetails,
  RouteOrderTargetMissingDetails,
  SyntheticKeyCollisionDetails,
  UnknownContributionKindDetails,
} from '../types.mjs';
import { BootError } from '../types.mjs';

// ---------------------------------------------------------------------------
// BootStage
// ---------------------------------------------------------------------------

describe('BootStage', () => {
  it('is exactly the six-stage literal union', () => {
    expectTypeOf<BootStage>().toEqualTypeOf<
      | 'validateManifests'
      | 'planBoot'
      | 'materializeComponents'
      | 'applyContributions'
      | 'freezeWorld'
      | 'assembleApp'
    >();
  });
});

// ---------------------------------------------------------------------------
// BootErrorReason — exactly 19 literals
// ---------------------------------------------------------------------------

describe('BootErrorReason', () => {
  it('contains exactly the 19 reason literals', () => {
    expectTypeOf<BootErrorReason>().toEqualTypeOf<
      | 'duplicate-module-name'
      | 'duplicate-provides'
      | 'bootstrap-component-collision'
      | 'synthetic-key-collision'
      | 'missing-required-component'
      | 'unknown-contribution-kind'
      | 'duplicate-contribute'
      | 'override-target-missing'
      | 'duplicate-override'
      | 'contribute-and-override-same-key'
      | 'list-shaped-override-not-allowed'
      | 'lifecycle-without-provides'
      | 'invalid-route-advertisement-path'
      | 'config-validation-failed'
      | 'circular-dependency'
      | 'provides-factory-failed'
      | 'contribute-factory-failed'
      | 'route-order-cycle'
      | 'route-order-target-missing'
    >();
  });
});

// ---------------------------------------------------------------------------
// Per-reason Details — discriminator type checks (all 19)
// ---------------------------------------------------------------------------

describe('per-reason *Details discriminators', () => {
  it('DuplicateModuleNameDetails.reason', () => {
    expectTypeOf<DuplicateModuleNameDetails['reason']>().toEqualTypeOf<'duplicate-module-name'>();
  });

  it('DuplicateProvidesDetails.reason', () => {
    expectTypeOf<DuplicateProvidesDetails['reason']>().toEqualTypeOf<'duplicate-provides'>();
  });

  it('BootstrapComponentCollisionDetails.reason', () => {
    expectTypeOf<BootstrapComponentCollisionDetails['reason']>().toEqualTypeOf<'bootstrap-component-collision'>();
  });

  it('SyntheticKeyCollisionDetails.reason', () => {
    expectTypeOf<SyntheticKeyCollisionDetails['reason']>().toEqualTypeOf<'synthetic-key-collision'>();
  });

  it('MissingRequiredComponentDetails.reason', () => {
    expectTypeOf<MissingRequiredComponentDetails['reason']>().toEqualTypeOf<'missing-required-component'>();
  });

  it('UnknownContributionKindDetails.reason', () => {
    expectTypeOf<UnknownContributionKindDetails['reason']>().toEqualTypeOf<'unknown-contribution-kind'>();
  });

  it('DuplicateContributeDetails.reason', () => {
    expectTypeOf<DuplicateContributeDetails['reason']>().toEqualTypeOf<'duplicate-contribute'>();
  });

  it('OverrideTargetMissingDetails.reason', () => {
    expectTypeOf<OverrideTargetMissingDetails['reason']>().toEqualTypeOf<'override-target-missing'>();
  });

  it('DuplicateOverrideDetails.reason', () => {
    expectTypeOf<DuplicateOverrideDetails['reason']>().toEqualTypeOf<'duplicate-override'>();
  });

  it('ContributeAndOverrideSameKeyDetails.reason', () => {
    expectTypeOf<ContributeAndOverrideSameKeyDetails['reason']>().toEqualTypeOf<'contribute-and-override-same-key'>();
  });

  it('ListShapedOverrideDetails.reason', () => {
    expectTypeOf<ListShapedOverrideDetails['reason']>().toEqualTypeOf<'list-shaped-override-not-allowed'>();
  });

  it('LifecycleWithoutProvidesDetails.reason', () => {
    expectTypeOf<LifecycleWithoutProvidesDetails['reason']>().toEqualTypeOf<'lifecycle-without-provides'>();
  });

  it('InvalidRouteAdvertisementPathDetails.reason', () => {
    expectTypeOf<InvalidRouteAdvertisementPathDetails['reason']>().toEqualTypeOf<'invalid-route-advertisement-path'>();
  });

  it('ConfigValidationFailedDetails.reason', () => {
    expectTypeOf<ConfigValidationFailedDetails['reason']>().toEqualTypeOf<'config-validation-failed'>();
  });

  it('CircularDependencyDetails.reason', () => {
    expectTypeOf<CircularDependencyDetails['reason']>().toEqualTypeOf<'circular-dependency'>();
  });

  it('ProvidesFactoryFailedDetails.reason', () => {
    expectTypeOf<ProvidesFactoryFailedDetails['reason']>().toEqualTypeOf<'provides-factory-failed'>();
  });

  it('ContributeFactoryFailedDetails.reason', () => {
    expectTypeOf<ContributeFactoryFailedDetails['reason']>().toEqualTypeOf<'contribute-factory-failed'>();
  });

  it('RouteOrderCycleDetails.reason', () => {
    expectTypeOf<RouteOrderCycleDetails['reason']>().toEqualTypeOf<'route-order-cycle'>();
  });

  it('RouteOrderTargetMissingDetails.reason', () => {
    expectTypeOf<RouteOrderTargetMissingDetails['reason']>().toEqualTypeOf<'route-order-target-missing'>();
  });
});

// ---------------------------------------------------------------------------
// BootErrorDetails discriminated union
// ---------------------------------------------------------------------------

describe('BootErrorDetails', () => {
  it('["reason"] extracts to exactly BootErrorReason', () => {
    expectTypeOf<BootErrorDetails['reason']>().toEqualTypeOf<BootErrorReason>();
  });
});

// ---------------------------------------------------------------------------
// BootError runtime behaviour
// ---------------------------------------------------------------------------

describe('BootError', () => {
  it('instantiates with all required fields', () => {
    const details: DuplicateModuleNameDetails = {
      reason: 'duplicate-module-name',
      name: 'auth-module',
      modules: ['mod-a', 'mod-b'],
    };
    const err = new BootError({
      message: 'Duplicate module name: auth-module',
      reason: 'duplicate-module-name',
      stage: 'validateManifests',
      details,
    });
    expect(err.name).toBe('BootError');
    expect(err.reason).toBe('duplicate-module-name');
    expect(err.stage).toBe('validateManifests');
    expect(err.details).toBe(details);
    expect(err.message).toBe('Duplicate module name: auth-module');
  });

  it('cause is undefined when omitted', () => {
    const err = new BootError({
      message: 'test',
      reason: 'duplicate-module-name',
      stage: 'validateManifests',
      details: { reason: 'duplicate-module-name', name: 'x', modules: ['a', 'b'] },
    });
    expect(err.cause).toBeUndefined();
  });

  it('preserves cause for *-factory-failed reasons (reference equality)', () => {
    const thrownValue = new Error('factory exploded');
    const details: ProvidesFactoryFailedDetails = {
      reason: 'provides-factory-failed',
      module: 'my-module',
      componentKey: 'nonexistent-key' as never,
      originalError: thrownValue,
    };
    const err = new BootError({
      message: 'Provider factory failed in my-module',
      reason: 'provides-factory-failed',
      stage: 'materializeComponents',
      details,
      cause: thrownValue,
    });
    expect(err.cause).toBe(thrownValue);
  });

  it('preserves cause for contribute-factory-failed reason (reference equality)', () => {
    const thrownValue = { code: 42, detail: 'oops' };
    const details: ContributeFactoryFailedDetails = {
      reason: 'contribute-factory-failed',
      module: 'contrib-module',
      kind: 'grants',
      name: 'authorization_code',
      originalError: thrownValue,
    };
    const err = new BootError({
      message: 'Contribution factory failed',
      reason: 'contribute-factory-failed',
      stage: 'applyContributions',
      details,
      cause: thrownValue,
    });
    expect(err.cause).toBe(thrownValue);
  });

  it('is an instance of Error', () => {
    const err = new BootError({
      message: 'test',
      reason: 'circular-dependency',
      stage: 'planBoot',
      details: { reason: 'circular-dependency', cycle: [] },
    });
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(BootError);
  });
});

// ---------------------------------------------------------------------------
// AppHandle field shape
// ---------------------------------------------------------------------------

describe('AppHandle', () => {
  it('has exactly the four expected keys', () => {
    expectTypeOf<keyof AppHandle>().toEqualTypeOf<'router' | 'listen' | 'dispose' | 'components'>();
  });
});

// ---------------------------------------------------------------------------
// DefaultBootstrapMap shape (spec §6.2)
// ---------------------------------------------------------------------------

describe('DefaultBootstrapMap', () => {
  it('declares the closed { config: AppConfig; pathResolver: PathResolver } shape per spec §6.2', () => {
    expectTypeOf<DefaultBootstrapMap>().toEqualTypeOf<{
      readonly config: AppConfig;
      readonly pathResolver: PathResolver;
    }>();
  });
});
