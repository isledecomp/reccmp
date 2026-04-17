import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('');
});

test.describe('Page title', () => {
  test('Should include binary filename', async ({ page }) => {
    await page.waitForLoadState();
    const title = await page.title();
    expect(title).toContain('isle.exe');
  });
});
