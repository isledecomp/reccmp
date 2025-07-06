import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('');
});

test.fixme('Reset filter options after reload (Issue #99)', async ({ page }) => {
  // Make sure the first option is selected on the first page load.
  const radio = page.getByRole('radio', { name: 'Name/address' });
  await expect(radio).toBeChecked();

  // Select one of the other options.
  await page.getByRole('radio', { name: 'Asm diffs only' }).click();

  // First option should be unselected.
  await expect(radio).not.toBeChecked();

  // The first option should be selected again after the reload.
  await page.reload();
  await expect(radio).toBeChecked();
});
