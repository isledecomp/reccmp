import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('');
});

test.describe('Column headers', () => {
  test('Invert order', async ({ page }) => {
    // Get (orig) address column header
    // TODO: improve locator
    const addressHeader = page.locator('thead').getByText(/Address/);

    // TODO: improve locator
    const topRow = page.locator('func-row').nth(0);

    // First address in test data
    await expect(topRow).toContainText('0x401000');

    // Invert sort order
    await addressHeader.click();

    // Last original address
    await expect(topRow).toContainText('0x8005d7');

    // Restore starting order
    await addressHeader.click();
    await expect(topRow).toContainText('0x401000');
  });

  test('Order retained if column changed', async ({ page }) => {
    // TODO: improve locators
    const addressHeader = page.locator('thead').getByText(/Address/);
    const nameHeader = page.locator('thead').getByText(/Name/);
    const topRow = page.locator('func-row').nth(0);

    // Should be sorted by orig address to start.
    await expect(topRow).toContainText('0x401000');

    // Sort by name instead
    await nameHeader.click();
    await expect(topRow).toContainText('??2@YAPAXI@Z');

    // Sort by address
    await addressHeader.click();
    await expect(topRow).toContainText('0x401000');

    // Invert order on address and change to name column
    await addressHeader.click();
    await nameHeader.click();

    // Now sorting by name in reverse alphabetical order.
    // Inverted sort on address retained for the new column.
    await expect(topRow).toContainText('_wctomb');
  });

  test('Update sort indicator', async ({ page }) => {
    // TODO: improve locators
    // We need to look for the triangle here...
    const container = page.locator('th').filter({ hasText: /Address/ });

    // ...but click this element to do the sort.
    const header = container.getByText('Address');

    // Start with ascending, then descending, then back to ascending.
    await expect(container).toContainText('▲');
    await header.click();
    await expect(container).toContainText('▼');
    await header.click();
    await expect(container).toContainText('▲');
  });
});
