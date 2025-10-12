import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('');
});

test.describe('Search bar', () => {
  test('Search by name', async ({ page }) => {
    const query = 'IsleApp';
    const searchbox = page.getByRole('searchbox');

    // Locators for rows matching and not matching our intended query.
    // TODO: use better locator for table rows/cells
    const notMatchRows = page.locator('tr[data-address]').filter({ hasNotText: query });
    const matchRows = page.locator('tr[data-address]').filter({ hasText: query });

    // Should have a variety of rows to start.
    await expect(notMatchRows).not.toHaveCount(0);
    await expect(matchRows).not.toHaveCount(0);

    // Fill out the search bar. (Assumes name search enabled by default.)
    await searchbox.fill(query);

    // Non-matching rows are gone.
    await expect(notMatchRows).toHaveCount(0);
    await expect(matchRows).not.toHaveCount(0);

    // Clear the box.
    await searchbox.clear();

    // All rows should return.
    await expect(notMatchRows).not.toHaveCount(0);
    await expect(matchRows).not.toHaveCount(0);
  });

  test('Search by address', async ({ page }) => {
    const searchbox = page.getByRole('searchbox');

    // TODO: use better locator for table rows/cells
    const rows = page.locator('tr[data-address]');

    // Make sure we have rows displayed.
    await expect(rows).not.toHaveCount(0);

    // Should match the first row's orig address.
    await searchbox.fill('0x401000');

    // Only one row should appear.
    await expect(rows).toHaveCount(1);
  });

  test('Changing filter type re-runs search', async ({ page }) => {
    const searchbox = page.getByRole('searchbox');
    const radio = page.getByRole('radio', { name: 'Asm output' });

    // TODO: use better locator for table rows/cells
    const rows = page.locator('tr[data-address]');

    // Make sure we have some rows
    await expect(rows).not.toHaveCount(0);

    // Run a search that we know will not match any names
    await searchbox.fill('mov eax');

    // Should filter out all rows.
    await expect(rows).toHaveCount(0);

    // Search on asm output instead
    await radio.click();

    // We should now have some results.
    await expect(rows).not.toHaveCount(0);
  });

  test('Changing filter type changes placeholder', async ({ page }) => {
    const searchbox = page.getByRole('searchbox');
    const namePlaceholder = page.getByPlaceholder('Search for offset or function name');
    const asmPlaceholder = page.getByPlaceholder('Search for instruction');

    // Should start with name placeholder
    await expect(searchbox.and(namePlaceholder)).toBeAttached();
    await expect(searchbox.and(asmPlaceholder)).not.toBeAttached();

    // Select another filter option
    await page.getByRole('radio', { name: 'Asm diffs only' }).click();

    // Should change placeholder
    await expect(searchbox.and(namePlaceholder)).not.toBeAttached();
    await expect(searchbox.and(asmPlaceholder)).toBeAttached();

    // Change back to name filtering
    await page.getByRole('radio', { name: 'Name/address' }).click();

    // Restore default placeholder
    await expect(searchbox.and(namePlaceholder)).toBeAttached();
    await expect(searchbox.and(asmPlaceholder)).not.toBeAttached();

    // Same behavior for asm diff option
    await page.getByRole('radio', { name: 'Asm diffs only' }).click();
    await expect(searchbox.and(namePlaceholder)).not.toBeAttached();
    await expect(searchbox.and(asmPlaceholder)).toBeAttached();
  });
});
