import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('');
});

test.describe('Diff rows', () => {
  test('Should add/remove element', async ({ page }) => {
    // Name text to click that toggles the diff row.
    const nameLink = page.locator('func-row').getByText('IsleApp::IsleApp');

    // There are none to start
    await expect(page.locator('diff-row')).toHaveCount(0);

    // Create diff-row element
    await nameLink.click();
    await expect(page.locator('diff-row')).toHaveCount(1);

    // Remove diff-row element
    await nameLink.click();
    await expect(page.locator('diff-row')).toHaveCount(0);
  });

  test('Should stay open after entity filtering', async ({ page }) => {
    const nameLink = page.locator('func-row').getByText('IsleApp::IsleApp');
    const searchbox = page.getByRole('searchbox');

    // TODO: Not sure of a better way to identify this element in the current design
    const diffRow = page.locator('diff-row[data-address="0x401000"]');

    // Diff row should appear when we toggle this entity.
    await nameLink.click();
    await expect(diffRow).toBeAttached();

    // Diff row should disappear when this entity is filtered out.
    await searchbox.fill('text-that-doesnt-match-anything');
    await expect(diffRow).not.toBeAttached();

    // Diff row was never closed. When the entity returns to view it should still be open.
    await searchbox.clear();
    await expect(diffRow).toBeAttached();
  });
});
