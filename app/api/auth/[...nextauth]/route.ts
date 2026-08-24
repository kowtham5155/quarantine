import { handlers } from '@/auth';

export const { GET, POST } = handlers;

// Prisma and argon2 are native modules; this route cannot run on the edge.
export const runtime = 'nodejs';
