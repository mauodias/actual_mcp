/**
 * Minimal single-user OAuth 2.1 authorization server provider.
 *
 * Protects the MCP server itself (not the Actual Budget account) for public
 * deployment. Dynamic client registration is open, per the MCP spec; the
 * authorize step shows our own login form instead of redirecting to a
 * third-party IdP, since there is exactly one user. Registered clients and
 * issued tokens are written to `stateFile` when one is given, so a restart
 * doesn't force every connected client to re-authenticate. Pending logins and
 * authorization codes live for minutes and stay in memory.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import type { Response } from 'express';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthorizationParams, OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { InvalidGrantError, InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { checkResourceAllowed } from '@modelcontextprotocol/sdk/shared/auth-utils.js';
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';

const ACCESS_TOKEN_TTL_SECONDS = 3600;
const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 3600;
const AUTH_CODE_TTL_SECONDS = 600;

interface PendingAuthorization {
  clientId: string;
  params: AuthorizationParams;
}

interface AuthorizationCode {
  clientId: string;
  params: AuthorizationParams;
  expiresAt: number;
}

interface IssuedToken {
  token: string;
  clientId: string;
  scopes: string[];
  expiresAt: number;
  resource: string;
}

interface PersistedState {
  clients: OAuthClientInformationFull[];
  accessTokens: IssuedToken[];
  refreshTokens: IssuedToken[];
}

export interface SingleUserOAuthOptions {
  username: string;
  password: string;
  /** This server's public URL; tokens are bound to it. */
  resourceServerUrl: URL;
  /** Where clients and tokens persist; memory only when unset. */
  stateFile?: string;
}

const now = (): number => Math.floor(Date.now() / 1000);
const newToken = (): string => randomBytes(32).toString('base64url');

const safeEqual = (a: string, b: string): boolean => {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  // Reason: timingSafeEqual throws on buffers of unequal length.
  return left.length === right.length && timingSafeEqual(left, right);
};

/**
 * OAuthServerProvider for exactly one (username, password) user.
 */
export class SingleUserOAuthProvider implements OAuthServerProvider {
  private readonly clients = new Map<string, OAuthClientInformationFull>();
  private readonly pending = new Map<string, PendingAuthorization>();
  private readonly codes = new Map<string, AuthorizationCode>();
  private readonly accessTokens = new Map<string, IssuedToken>();
  private readonly refreshTokens = new Map<string, IssuedToken>();

  constructor(private readonly options: SingleUserOAuthOptions) {
    this.loadState();
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return {
      getClient: (clientId: string) => this.clients.get(clientId),
      registerClient: (client: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>) => {
        const registered: OAuthClientInformationFull = {
          ...client,
          client_id: randomUUID(),
          client_id_issued_at: now(),
        };
        this.clients.set(registered.client_id, registered);
        this.saveState();
        return registered;
      },
    };
  }

  checkCredentials(username: string, password: string): boolean {
    // Reason: evaluate both comparisons so a wrong username takes as long as a wrong password.
    const userOk = safeEqual(username, this.options.username);
    const passwordOk = safeEqual(password, this.options.password);
    return userOk && passwordOk;
  }

  // ------------------------------------------------------------------
  // Authorization (login form instead of a third-party redirect)
  // ------------------------------------------------------------------

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const loginId = randomBytes(24).toString('base64url');
    this.pending.set(loginId, { clientId: client.client_id, params });
    res.redirect(302, `/login?login_id=${encodeURIComponent(loginId)}`);
  }

  popPending(loginId: string): PendingAuthorization | undefined {
    const pending = this.pending.get(loginId);
    this.pending.delete(loginId);
    return pending;
  }

  /** Re-store a pending authorization after a failed login attempt. */
  restorePending(loginId: string, pending: PendingAuthorization): void {
    this.pending.set(loginId, pending);
  }

  /** Issue an authorization code and return the client's redirect URL. */
  completeAuthorization(pending: PendingAuthorization): string {
    const code = newToken();
    this.codes.set(code, { ...pending, expiresAt: now() + AUTH_CODE_TTL_SECONDS });
    const redirect = new URL(pending.params.redirectUri);
    redirect.searchParams.set('code', code);
    if (pending.params.state !== undefined) {
      redirect.searchParams.set('state', pending.params.state);
    }
    return redirect.href;
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    return this.loadCode(client, authorizationCode).params.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL
  ): Promise<OAuthTokens> {
    const code = this.loadCode(client, authorizationCode);
    this.codes.delete(authorizationCode); // single use
    if (redirectUri !== undefined && redirectUri !== code.params.redirectUri) {
      throw new InvalidGrantError('redirect_uri does not match the authorization request');
    }
    return this.issueTokens(client.client_id, code.params.scopes ?? [], resource ?? code.params.resource);
  }

  // ------------------------------------------------------------------
  // Refresh
  // ------------------------------------------------------------------

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL
  ): Promise<OAuthTokens> {
    const stored = this.refreshTokens.get(refreshToken);
    if (!stored || stored.clientId !== client.client_id || stored.expiresAt <= now()) {
      throw new InvalidGrantError('Invalid refresh token');
    }
    this.refreshTokens.delete(refreshToken); // rotate; issueTokens saves
    return this.issueTokens(
      client.client_id,
      scopes && scopes.length > 0 ? scopes : stored.scopes,
      resource ?? new URL(stored.resource)
    );
  }

  // ------------------------------------------------------------------
  // Access tokens
  // ------------------------------------------------------------------

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const stored = this.accessTokens.get(token);
    if (!stored || stored.expiresAt <= now()) {
      this.accessTokens.delete(token);
      throw new InvalidTokenError('Invalid or expired access token');
    }
    if (
      !checkResourceAllowed({
        requestedResource: stored.resource,
        configuredResource: this.options.resourceServerUrl,
      })
    ) {
      throw new InvalidTokenError('Token was issued for a different resource');
    }
    return {
      token,
      clientId: stored.clientId,
      scopes: stored.scopes,
      expiresAt: stored.expiresAt,
      resource: new URL(stored.resource),
    };
  }

  async revokeToken(_client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    this.accessTokens.delete(request.token);
    this.refreshTokens.delete(request.token);
    this.saveState();
  }

  // ------------------------------------------------------------------
  // Internal
  // ------------------------------------------------------------------

  private loadCode(client: OAuthClientInformationFull, authorizationCode: string): AuthorizationCode {
    const code = this.codes.get(authorizationCode);
    if (!code || code.clientId !== client.client_id || code.expiresAt <= now()) {
      throw new InvalidGrantError('Invalid authorization code');
    }
    return code;
  }

  private issueTokens(clientId: string, scopes: string[], resource: URL | undefined): OAuthTokens {
    // Reason: clients aren't required to send an RFC 8707 resource indicator; when
    // they don't, self-assign our own URL so verifyAccessToken still accepts tokens we issued.
    const boundResource = (resource ?? this.options.resourceServerUrl).href;
    const accessToken = newToken();
    const refreshToken = newToken();
    const issuedAt = now();
    this.accessTokens.set(accessToken, {
      token: accessToken,
      clientId,
      scopes,
      expiresAt: issuedAt + ACCESS_TOKEN_TTL_SECONDS,
      resource: boundResource,
    });
    this.refreshTokens.set(refreshToken, {
      token: refreshToken,
      clientId,
      scopes,
      expiresAt: issuedAt + REFRESH_TOKEN_TTL_SECONDS,
      resource: boundResource,
    });
    this.saveState();
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      refresh_token: refreshToken,
      ...(scopes.length > 0 ? { scope: scopes.join(' ') } : {}),
    };
  }

  private loadState(): void {
    const { stateFile } = this.options;
    if (!stateFile || !existsSync(stateFile)) {
      return;
    }
    try {
      const data = JSON.parse(readFileSync(stateFile, 'utf8')) as PersistedState;
      const current = now();
      for (const client of data.clients) this.clients.set(client.client_id, client);
      for (const t of data.accessTokens) if (t.expiresAt > current) this.accessTokens.set(t.token, t);
      for (const t of data.refreshTokens) if (t.expiresAt > current) this.refreshTokens.set(t.token, t);
    } catch (err) {
      console.error(`Ignoring unreadable OAuth state in ${stateFile}; clients will re-authenticate:`, err);
      this.clients.clear();
      this.accessTokens.clear();
      this.refreshTokens.clear();
    }
  }

  private saveState(): void {
    const { stateFile } = this.options;
    if (!stateFile) {
      return;
    }
    const data: PersistedState = {
      clients: [...this.clients.values()],
      accessTokens: [...this.accessTokens.values()],
      refreshTokens: [...this.refreshTokens.values()],
    };
    mkdirSync(dirname(stateFile), { recursive: true });
    const tmp = `${stateFile}.tmp`;
    writeFileSync(tmp, JSON.stringify(data));
    chmodSync(tmp, 0o600);
    renameSync(tmp, stateFile);
  }
}
