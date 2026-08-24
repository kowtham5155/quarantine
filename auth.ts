import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';

import { authConfig, SESSION_ABSOLUTE_SECONDS } from '@/auth.config';
import { prisma } from '@/lib/db';
import { logger } from '@/lib/logger';
import { hashToken, issueToken, safeEqualHex } from '@/lib/tokens';
import '@/lib/auth-types';

/**
 * Auth.js instance (Node runtime).
 *
 * The credentials provider never sees a password. Step one of the login flow
 * (lib/services/auth.service.ts → beginLogin) verifies the password and any
 * TOTP code, then issues a single-use LoginChallenge. All this provider does is
 * consume that challenge, which keeps password handling in the service layer
 * where it is rate limited and audited, and means the password does not have to
 * be held in the browser across the TOTP prompt.
 */

const challengeSchema = z.object({
  challengeToken: z.string().min(20).max(200),
});

/** Consume a login challenge and return the user it authenticates. */
async function consumeChallenge(challengeToken: string) {
  const tokenHash = hashToken(challengeToken);

  const challenge = await prisma.loginChallenge.findUnique({
    where: { tokenHash },
    include: { user: true },
  });

  if (!challenge) return null;

  // Timing-safe even though the lookup was by digest — the comparison keeps the
  // check uniform with every other token path in the codebase.
  if (!safeEqualHex(challenge.tokenHash, tokenHash)) return null;
  if (challenge.consumedAt) return null;
  if (challenge.expiresAt.getTime() <= Date.now()) return null;
  // A challenge is only issued once the second factor has already been
  // satisfied; one that still wants TOTP was never completed.
  if (challenge.totpRequired) return null;

  // Single use: consume it before returning, and only if it was still unconsumed.
  const consumed = await prisma.loginChallenge.updateMany({
    where: { id: challenge.id, consumedAt: null },
    data: { consumedAt: new Date() },
  });
  if (consumed.count !== 1) return null;

  return challenge;
}

export const { handlers, signIn, signOut, auth } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      id: 'challenge',
      name: 'Quarantine',
      credentials: {
        challengeToken: { label: 'Challenge', type: 'text' },
      },
      async authorize(raw) {
        const parsed = challengeSchema.safeParse(raw);
        if (!parsed.success) return null;

        const challenge = await consumeChallenge(parsed.data.challengeToken);
        if (!challenge) return null;

        const user = challenge.user;

        // Default org: the first membership, most privileged first.
        const membership = await prisma.membership.findFirst({
          where: { userId: user.id, org: { deletedAt: null } },
          orderBy: [{ role: 'asc' }, { createdAt: 'asc' }],
        });

        // Session row is the revocation list. The JWT carries the plaintext
        // token; only its digest is stored.
        const session = issueToken(SESSION_ABSOLUTE_SECONDS * 1000);
        const now = Date.now();

        await prisma.session.create({
          data: {
            userId: user.id,
            tokenHash: session.tokenHash,
            ip: challenge.ip,
            userAgent: challenge.userAgent,
            expiresAt: new Date(now + SESSION_ABSOLUTE_SECONDS * 1000),
          },
        });

        await prisma.user.update({
          where: { id: user.id },
          data: { lastLoginAt: new Date(), failedLoginCount: 0, lockedUntil: null },
        });

        logger.info({ userId: user.id, orgId: membership?.orgId }, 'session established');

        return {
          id: user.id,
          email: user.email,
          name: user.name,
          sid: session.token,
          orgId: membership?.orgId ?? null,
          role: membership?.role ?? null,
          absoluteExpiry: Math.floor(now / 1000) + SESSION_ABSOLUTE_SECONDS,
        };
      },
    }),
  ],
  callbacks: {
    ...authConfig.callbacks,

    async jwt({ token, user, trigger, session }) {
      if (user) {
        token.userId = user.id;
        token.sid = user.sid;
        token.orgId = user.orgId ?? null;
        token.role = user.role ?? null;
        token.absoluteExpiry = user.absoluteExpiry;
        return token;
      }

      // Org switch: re-read the membership rather than trusting the client.
      if (trigger === 'update' && session && typeof session === 'object') {
        const requestedOrgId = (session as { activeOrgId?: unknown }).activeOrgId;
        if (typeof requestedOrgId === 'string' && token.userId) {
          const membership = await prisma.membership.findUnique({
            where: { userId_orgId: { userId: token.userId, orgId: requestedOrgId } },
            include: { org: { select: { deletedAt: true } } },
          });
          if (membership && !membership.org.deletedAt) {
            token.orgId = membership.orgId;
            token.role = membership.role;
          }
        }
      }

      return token;
    },

    session({ session, token }) {
      // Session["user"] is intersected with AdapterUser, which requires
      // emailVerified even though this app never uses the adapter.
      session.user = {
        id: token.userId ?? '',
        email: session.user?.email ?? '',
        name: session.user?.name ?? '',
        emailVerified: null,
        orgId: token.orgId ?? null,
        role: token.role ?? null,
      };
      session.sid = token.sid ?? '';
      session.absoluteExpiry = token.absoluteExpiry ?? 0;
      return session;
    },
  },

  events: {
    async signOut(message) {
      // Revoke the Session row so the JWT cannot be replayed before it expires.
      const sid = 'token' in message ? message.token?.sid : undefined;
      if (!sid) return;
      await prisma.session.updateMany({
        where: { tokenHash: hashToken(sid), revokedAt: null },
        data: { revokedAt: new Date() },
      });
    },
  },
});
