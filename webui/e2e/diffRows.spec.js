import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('');
});

test.describe('Diff rows', () => {
  test('Should add/remove element', async ({ page }) => {
    // Name text to click that toggles the diff row.
    const nameLink = page.locator('tr[data-address]').getByText('IsleApp::IsleApp');

    // There are none to start
    await expect(page.locator('tr[data-diff]')).toHaveCount(0);

    // Create diff-row element
    await nameLink.click();
    await expect(page.locator('tr[data-diff]')).toHaveCount(1);

    // Remove diff-row element
    await nameLink.click();
    await expect(page.locator('tr[data-diff]')).toHaveCount(0);
  });

  test('"No diff" message', async ({ page }) => {
    // Get the first row with 100% score (and not an effective match)
    const matchRow = page.locator('tr[data-address]', { hasText: '100.00%', exact: true }).nth(0);
    // TODO: This highlights a potential design flaw: there is no obvious indication that
    // clicking the name (and only the name) of the row will expand the diff display.
    const link = matchRow.locator('td[data-col="name"]');

    // Make sure there are no diff rows (so our next locator can cast a wide net)
    await expect(page.locator('tr[data-diff]')).toHaveCount(0);

    // Expand the diff
    await link.click();

    // Should now see the "no diff" message
    await expect(page.locator('tr[data-diff]').getByText('no diff')).toBeAttached();

    // Close the diff row
    await link.click();

    // The message should be gone
    await expect(page.locator('tr[data-diff]').getByText('no diff')).not.toBeAttached();
  });

  test('"Stub" message', async ({ page }) => {
    // Get the first stub
    const stubRow = page.locator('tr[data-address]', { hasText: 'stub', exact: true }).nth(0);
    const link = stubRow.locator('td[data-col="name"]');

    // Make sure there are no diff rows (so our next locator can look for any diff-row element)
    await expect(page.locator('tr[data-diff]')).toHaveCount(0);

    // Expand the diff
    await link.click();

    // Should now see the "no diff" message
    await expect(page.locator('tr[data-diff]').getByText('no diff')).toBeAttached();

    // Close the diff row
    await link.click();

    // The message should be gone
    await expect(page.locator('tr[data-diff]').getByText('no diff')).not.toBeAttached();
  });

  test('Diff display', async ({ page }) => {
    // Filter the results
    await page.getByRole('checkbox', { name: /Hide 100%/ }).click();
    await page.getByRole('checkbox', { name: /Hide stubs/ }).click();

    // Make sure there are no diff rows (so our next locator can look for any diff-row element)
    await expect(page.locator('tr[data-diff]')).toHaveCount(0);

    // Expand diff row
    const topRow = page.locator('tr[data-address]').nth(0);
    await topRow.locator('td[data-col="name"]').click();

    // Searching for unified diff display elements.
    await expect(page.locator('tr[data-diff]')).toContainText('---');
    await expect(page.locator('tr[data-diff]')).toContainText('+++');
  });

  test('Should stay open after entity filtering', async ({ page }) => {
    const nameLink = page.locator('tr[data-address]').getByText('IsleApp::IsleApp');
    const searchbox = page.getByRole('searchbox');
    const diffRow = page.locator('tr[data-diff]');

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
