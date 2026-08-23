import { expect, test } from '@playwright/test';

test.describe('public shell', () => {
  test('landing page renders the product framing and verdict scale', async ({ page }) => {
    await page.goto('/');

    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Scan a package' }).first()).toBeVisible();
    await expect(page.getByText('Known malicious')).toBeVisible();
  });

  test('sends the baseline security headers', async ({ page }) => {
    const response = await page.goto('/');
    const headers = response?.headers() ?? {};

    expect(headers['x-frame-options']).toBe('DENY');
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(headers['content-security-policy']).toContain('nonce-');
  });

  test('redirects an unauthenticated visitor away from the dashboard', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/login\?next=%2Fdashboard/);
  });
});
