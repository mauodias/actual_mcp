import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Response } from 'express';
import { describe, expect, it } from 'vitest';
import type { OAuthClientInformationFull, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { SingleUserOAuthProvider } from './single-user-oauth.js';

const URL_ = new URL('https://actual.example/');
const REDIRECT = 'https://claude.ai/cb';

const provider = (stateFile?: string): SingleUserOAuthProvider =>
  new SingleUserOAuthProvider({ username: 'u', password: 'p', resourceServerUrl: URL_, stateFile });

const register = async (p: SingleUserOAuthProvider): Promise<OAuthClientInformationFull> =>
  p.clientsStore.registerClient!({ redirect_uris: [REDIRECT] });

/** Runs authorize → login → code exchange, returning the redirect URL and tokens. */
interface SignIn {
  redirect: URL;
  code: string;
  tokens: OAuthTokens;
}

const signIn = async (
  p: SingleUserOAuthProvider,
  client: OAuthClientInformationFull,
  resource?: URL
): Promise<SignIn> => {
  let location = '';
  const res = { redirect: (_status: number, url: string) => (location = url) } as unknown as Response;
  await p.authorize(client, { codeChallenge: 'challenge', redirectUri: REDIRECT, state: 's1', resource }, res);
  const loginId = new URL(location, URL_).searchParams.get('login_id')!;
  const pending = p.popPending(loginId)!;
  const redirect = new URL(p.completeAuthorization(pending));
  const code = redirect.searchParams.get('code')!;
  expect(await p.challengeForAuthorizationCode(client, code)).toBe('challenge');
  const tokens = await p.exchangeAuthorizationCode(client, code, undefined, REDIRECT);
  return { redirect, code, tokens };
};

const stateFile = (): string => join(mkdtempSync(join(tmpdir(), 'oauth-')), 'oauth.json');

describe('SingleUserOAuthProvider', () => {
  it('issues tokens through the login flow and verifies them', async () => {
    const p = provider();
    const client = await register(p);
    const { redirect, tokens } = await signIn(p, client);

    expect(redirect.origin + redirect.pathname).toBe(REDIRECT);
    expect(redirect.searchParams.get('state')).toBe('s1');
    const info = await p.verifyAccessToken(tokens.access_token);
    expect(info.clientId).toBe(client.client_id);
    expect(info.resource?.href).toBe(URL_.href);
  });

  it('accepts only the configured credentials', () => {
    const p = provider();
    expect(p.checkCredentials('u', 'p')).toBe(true);
    expect(p.checkCredentials('u', 'wrong')).toBe(false);
    expect(p.checkCredentials('someone', 'p')).toBe(false);
    expect(p.checkCredentials('', '')).toBe(false);
  });

  it('uses each authorization code once', async () => {
    const p = provider();
    const client = await register(p);
    const { code } = await signIn(p, client);
    await expect(p.exchangeAuthorizationCode(client, code)).rejects.toThrow('Invalid authorization code');
  });

  it('rejects a code redeemed by another client', async () => {
    const p = provider();
    const client = await register(p);
    const other = await register(p);
    let location = '';
    const res = { redirect: (_s: number, url: string) => (location = url) } as unknown as Response;
    await p.authorize(client, { codeChallenge: 'c', redirectUri: REDIRECT }, res);
    const pending = p.popPending(new URL(location, URL_).searchParams.get('login_id')!)!;
    const code = new URL(p.completeAuthorization(pending)).searchParams.get('code')!;
    await expect(p.exchangeAuthorizationCode(other, code)).rejects.toThrow('Invalid authorization code');
  });

  it('rejects tokens bound to another resource', async () => {
    const p = provider();
    const client = await register(p);
    const { tokens } = await signIn(p, client, new URL('https://elsewhere.example/mcp'));
    await expect(p.verifyAccessToken(tokens.access_token)).rejects.toThrow('different resource');
  });

  it('accepts tokens bound to a path under this server', async () => {
    const p = provider();
    const client = await register(p);
    const { tokens } = await signIn(p, client, new URL('https://actual.example/mcp'));
    await expect(p.verifyAccessToken(tokens.access_token)).resolves.toMatchObject({ clientId: client.client_id });
  });

  it('rejects unknown and revoked access tokens', async () => {
    const p = provider();
    const client = await register(p);
    const { tokens } = await signIn(p, client);
    await p.revokeToken(client, { token: tokens.access_token });
    await expect(p.verifyAccessToken(tokens.access_token)).rejects.toThrow('Invalid or expired');
    await expect(p.verifyAccessToken('nope')).rejects.toThrow('Invalid or expired');
  });

  it('rotates refresh tokens', async () => {
    const p = provider();
    const client = await register(p);
    const { tokens } = await signIn(p, client);
    const next = await p.exchangeRefreshToken(client, tokens.refresh_token!);
    expect(next.refresh_token).not.toBe(tokens.refresh_token);
    await expect(p.exchangeRefreshToken(client, tokens.refresh_token!)).rejects.toThrow('Invalid refresh token');
  });

  it('keeps clients and tokens across a restart', async () => {
    const file = stateFile();
    const first = provider(file);
    const client = await register(first);
    const { tokens } = await signIn(first, client);

    const second = provider(file);
    expect(await second.clientsStore.getClient(client.client_id)).toBeDefined();
    await expect(second.verifyAccessToken(tokens.access_token)).resolves.toBeDefined();

    // Rotation is persisted too: the old refresh token is gone after a restart.
    const next = await second.exchangeRefreshToken(client, tokens.refresh_token!);
    const third = provider(file);
    await expect(third.exchangeRefreshToken(client, tokens.refresh_token!)).rejects.toThrow();
    await expect(third.exchangeRefreshToken(client, next.refresh_token!)).resolves.toBeDefined();
  });

  it('starts empty when the state file is unreadable', async () => {
    const file = stateFile();
    writeFileSync(file, '{not json');
    const p = provider(file);
    expect(await p.clientsStore.getClient('anything')).toBeUndefined();
  });
});
