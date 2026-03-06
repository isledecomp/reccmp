import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('');
});

test('Reset filter options after reload (Issue #99)', async ({ page }) => {
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

test('Reset checkboxes after reload', async ({ page }) => {
  const checkboxes = [
    page.getByRole('checkbox', { name: /Hide 100%/ }),
    page.getByRole('checkbox', { name: /Show recomp/ }),
    page.getByRole('checkbox', { name: /Hide stubs/ }),
  ];

  // Make sure nothing is checked on the first load.
  for (const checkbox of checkboxes) {
    await expect(checkbox).not.toBeChecked();
  }

  // Check all three boxes.
  for (const checkbox of checkboxes) {
    await checkbox.click();
    await expect(checkbox).toBeChecked();
  }

  // They should be unchecke when we reload the page.
  await page.reload();
  for (const checkbox of checkboxes) {
    await expect(checkbox).not.toBeChecked();
  }
});
