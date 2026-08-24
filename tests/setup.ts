import { config } from 'dotenv';

/**
 * Unit tests import modules that reach `lib/env.ts` at import time, which
 * validates the environment and throws if it is incomplete. Loading .env.local
 * here means tests see the same contract the app does rather than a bypass.
 */
config({ path: '.env.local', quiet: true });
