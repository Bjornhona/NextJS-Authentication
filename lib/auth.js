import {cookies} from 'next/headers';
import {Lucia} from 'lucia';
import {BetterSqlite3Adapter} from '@lucia-auth/adapter-sqlite';
import db from './db';

const adapter = new BetterSqlite3Adapter(db, {user: 'users', session: 'sessions'});
const lucia = new Lucia(adapter, {
  sessionCookie: {
    expires: false,
    attributes: {
      secure: process.env.NODE_ENV !== 'production'
    }
  }
});

export const createAuthSession = async (userId) => {
  const session = await lucia.createSession(userId, {});
  const sessionCookie = lucia.createSessionCookie(session.id);
  // For NextJS versio 15 or higher cookies function needs await: (await cookies()).set...
  cookies().set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
}

export const verifyAuth = async () => {
  const emptyUserSession = {
    user: null,
    session: null
  };
  const sessionCookie = cookies().get(lucia.sessionCookieName);
  if (!sessionCookie) {
    return emptyUserSession;
  }

  const sessionId = sessionCookie.value;
  if (!sessionId) {
    return emptyUserSession;
  }

  const result = await lucia.validateSession(sessionId);

  try {
    if (result.session && result.session.fresh) {
      const sessionCookie = lucia.createSessionCookie(result.session.id);
      cookies().set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
    }
    if (!result.session) {
      const sessionCookie = lucia.createBlankSessionCookie();
      cookies().set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
    }
  } catch {};

  return result;
}

export const destroyAuthSession = async () => {
  // 1) Check if user has a valid session
  const {session} = await verifyAuth();

  if (!session) {
    return { error: 'Unauthorized!'}
  }

  // 2) Invalidate and destroy the cookie
  await lucia.invalidateSession(session.id);
  const sessionCookie = lucia.createBlankSessionCookie();
  cookies().set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
}
