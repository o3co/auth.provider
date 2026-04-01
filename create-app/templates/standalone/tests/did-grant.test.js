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
import { describe, it, expect } from 'vitest';
import axios from 'axios';
import * as ed from '@noble/ed25519';
import crypto from 'node:crypto';

const BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000';

const client = axios.create({
  baseURL: BASE_URL,
  validateStatus: () => true,
});

// Helper: generate a valid DID auth request body
const createDidAuthRequest = async (overrides = {}) => {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);

  const did = 'did:example:registry.example.com:org:test';
  const nonce = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const audience = 'https://api.example.com';

  const message = JSON.stringify({ did, timestamp, nonce, audience });
  const messageBytes = new TextEncoder().encode(message);
  const signature = await ed.signAsync(messageBytes, privateKey);

  return {
    grant_type: 'did',
    did,
    signature: Buffer.from(signature).toString('base64'),
    message,
    publicKey: Buffer.from(publicKey).toString('base64'),
    // Expose internals for test manipulation
    _privateKey: privateKey,
    _publicKey: publicKey,
    _nonce: nonce,
    ...overrides,
  };
};

describe('POST /oauth/token grant_type=did', () => {
  it('returns a JWT access token for a valid DID authentication', async () => {
    const body = await createDidAuthRequest();
    const res = await client.post('/oauth/token', body);

    expect(res.status).toBe(200);
    expect(res.data.access_token).toBeDefined();
    expect(res.data.token_type).toBe('Bearer');
    // M2M: no refresh token
    expect(res.data.refresh_token).toBeUndefined();
  });

  it('returns 401 for an invalid signature', async () => {
    const body = await createDidAuthRequest();
    // Corrupt the signature
    body.signature = Buffer.from('invalid-signature-data-that-is-long-enough-to-be-64-bytes-padding!!')
      .toString('base64');

    const res = await client.post('/oauth/token', body);
    expect(res.status).toBe(401);
    expect(res.data.error).toBe('invalid_grant');
  });

  it('returns 400 for an expired timestamp', async () => {
    const privateKey = ed.utils.randomPrivateKey();
    const publicKey = await ed.getPublicKeyAsync(privateKey);

    const did = 'did:example:registry.example.com:org:test';
    // Timestamp 10 minutes ago (exceeds 5 minute max age)
    const timestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const nonce = crypto.randomUUID();

    const message = JSON.stringify({ did, timestamp, nonce });
    const messageBytes = new TextEncoder().encode(message);
    const signature = await ed.signAsync(messageBytes, privateKey);

    const res = await client.post('/oauth/token', {
      grant_type: 'did',
      did,
      signature: Buffer.from(signature).toString('base64'),
      message,
      publicKey: Buffer.from(publicKey).toString('base64'),
    });

    expect(res.status).toBe(400);
    expect(res.data.error).toBe('invalid_request');
    expect(res.data.error_description).toContain('timestamp');
  });

  it('returns 400 on nonce replay (same nonce used twice)', async () => {
    const body = await createDidAuthRequest();

    // First request should succeed
    const res1 = await client.post('/oauth/token', body);
    expect(res1.status).toBe(200);

    // Second request with the same body (same nonce) should fail
    const res2 = await client.post('/oauth/token', body);
    expect(res2.status).toBe(400);
    expect(res2.data.error).toBe('invalid_request');
    expect(res2.data.error_description).toContain('nonce');
  });

  it('returns 400 when required fields are missing', async () => {
    // Missing did
    const res1 = await client.post('/oauth/token', {
      grant_type: 'did',
      signature: 'abc',
      message: '{}',
    });
    expect(res1.status).toBe(400);
    expect(res1.data.error).toBe('invalid_request');

    // Missing signature
    const res2 = await client.post('/oauth/token', {
      grant_type: 'did',
      did: 'did:example:test',
      message: '{}',
    });
    expect(res2.status).toBe(400);

    // Missing message
    const res3 = await client.post('/oauth/token', {
      grant_type: 'did',
      did: 'did:example:test',
      signature: 'abc',
    });
    expect(res3.status).toBe(400);
  });

  it('returns 400 when message is not valid JSON', async () => {
    const res = await client.post('/oauth/token', {
      grant_type: 'did',
      did: 'did:example:test',
      signature: 'abc',
      message: 'not-json',
      publicKey: 'abc',
    });
    expect(res.status).toBe(400);
    expect(res.data.error_description).toContain('valid JSON');
  });

  it('returns 400 when message.did does not match top-level did', async () => {
    const res = await client.post('/oauth/token', {
      grant_type: 'did',
      did: 'did:example:one',
      signature: 'abc',
      message: JSON.stringify({
        did: 'did:example:other',
        timestamp: new Date().toISOString(),
        nonce: crypto.randomUUID(),
      }),
      publicKey: 'abc',
    });
    expect(res.status).toBe(400);
    expect(res.data.error_description).toContain('must match');
  });

  it('returns 400 when publicKey is missing', async () => {
    const did = 'did:example:test';
    const message = JSON.stringify({
      did,
      timestamp: new Date().toISOString(),
      nonce: crypto.randomUUID(),
    });

    const res = await client.post('/oauth/token', {
      grant_type: 'did',
      did,
      signature: 'abc',
      message,
    });
    expect(res.status).toBe(400);
    expect(res.data.error_description).toContain('publicKey');
  });
});
