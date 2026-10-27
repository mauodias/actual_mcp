import express, { Request, Response, Router } from 'express';
import type { SingleUserOAuthProvider } from './single-user-oauth.js';

const escapeHtml = (value: string): string => value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/**
 * Renders the sign-in page that the authorize step redirects to.
 *
 * @param loginId - The pending authorization this form completes
 * @param error - Shown above the form after a failed attempt
 * @returns The page's HTML
 */
export function loginForm(loginId: string, error = ''): string {
  return `<!doctype html><title>Actual MCP login</title>
<body style="font-family:system-ui;max-width:320px;margin:4rem auto">
<h2>Sign in</h2>
${error ? `<p style="color:red">${escapeHtml(error)}</p>` : ''}
<form method="post">
<input type="hidden" name="login_id" value="${escapeHtml(loginId)}">
<p><input name="username" placeholder="Username" autofocus style="width:100%"></p>
<p><input name="password" type="password" placeholder="Password" style="width:100%"></p>
<button type="submit" style="width:100%">Sign in</button>
</form>
</body>
`;
}

/**
 * Serves GET and POST /login, which turn a pending authorization into an
 * authorization code once the single user's credentials check out.
 *
 * @param provider - The provider holding pending authorizations
 * @returns An Express router to install at the application root
 */
export function loginRouter(provider: SingleUserOAuthProvider): Router {
  const router = express.Router();
  router.use('/login', express.urlencoded({ extended: false }));

  router.get('/login', (req: Request, res: Response) => {
    const loginId = typeof req.query.login_id === 'string' ? req.query.login_id : '';
    res.type('html').send(loginForm(loginId));
  });

  router.post('/login', (req: Request, res: Response) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const field = (name: string): string => (typeof body[name] === 'string' ? (body[name] as string) : '');
    const loginId = field('login_id');
    const pending = provider.popPending(loginId);
    if (!pending) {
      res.status(400).type('text').send('Login expired, please retry from your client.');
      return;
    }
    if (!provider.checkCredentials(field('username'), field('password'))) {
      provider.restorePending(loginId, pending);
      res.status(401).type('html').send(loginForm(loginId, 'Invalid credentials'));
      return;
    }
    res.redirect(302, provider.completeAuthorization(pending));
  });

  return router;
}
