import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('');
});

async function fillSearchbox(page, query) {
  const searchbox = page.getByRole('searchbox');
  await searchbox.fill(query);
}

async function toggleRowByName(page, name) {
  await page.locator('td[data-col="name"]').filter({ hasText: name }).click();
}

async function getDiffRowByName(page, name) {
  const row = page.locator('tr[data-address]').filter({ hasText: name });
  return row.locator('xpath=./following-sibling::tr[@data-diff]').nth(0);
}

async function getDiffRow(page, name) {
  // Isolate the test case in the table
  await fillSearchbox(page, name);
  await toggleRowByName(page, name);
  // return page.locator('tr[data-diff]').nth(0);
  return getDiffRowByName(page, name);
}

test('Starting values', async ({ page }) => {
  const diffRow = await getDiffRow(page, 'IsleApp::SetupVideoFlags');

  const origOnlyAddr = '0x401561';
  const recompOnlyAddr = '0x40156b';

  // Verify that we are seeing instructions from each diff category:
  // insert/replace/delete and equal
  await expect(diffRow).toContainText('+mov');
  await expect(diffRow).toContainText('-mov');
  await expect(diffRow).toContainText('push');

  // This addr is only used in the orig address space. It should be visible by default.
  await expect(diffRow.getByText(origOnlyAddr)).toBeVisible();

  // This addr is only used in the recomp address space. It should be hidden by default.
  await expect(diffRow.getByText(recompOnlyAddr)).not.toBeVisible();
});

test('Addr display radio button', async ({ page }) => {
  const diffRow = await getDiffRow(page, 'IsleApp::SetupVideoFlags');

  const origOnlyAddr = '0x401561';
  const recompOnlyAddr = '0x40156b';

  await diffRow.getByRole('radio', { name: 'None' }).click();
  await expect(diffRow.getByText(origOnlyAddr)).not.toBeVisible();
  await expect(diffRow.getByText(recompOnlyAddr)).not.toBeVisible();

  await diffRow.getByRole('radio', { name: 'Original' }).click();
  await expect(diffRow.getByText(origOnlyAddr)).toBeVisible();
  await expect(diffRow.getByText(recompOnlyAddr)).not.toBeVisible();

  await diffRow.getByRole('radio', { name: 'Both' }).click();
  await expect(diffRow.getByText(origOnlyAddr)).toBeVisible();
  await expect(diffRow.getByText(recompOnlyAddr)).toBeVisible();
});

test('Addr display choice reverts when list changes', async ({ page }) => {
  const diffRow = await getDiffRow(page, 'IsleApp::SetupVideoFlags');

  // Should start with only original addresses shown.
  await expect(diffRow.getByRole('radio', { name: 'Original' })).toBeChecked();

  // Change to show orig and recomp addresses.
  await diffRow.getByRole('radio', { name: 'Both' }).click();
  await expect(diffRow.getByRole('radio', { name: 'Both' })).toBeChecked();

  // Change searchbox so we "reload" the list of entities.
  await fillSearchbox(page, 'IsleApp::SetupVideo');

  // Reverts to showing original addresses only.
  await expect(diffRow.getByRole('radio', { name: 'Original' })).toBeChecked();
});

test('Addr display choice is independent', async ({ page }) => {
  // Prepare two diff rows.
  await fillSearchbox(page, '@_shi');
  await toggleRowByName(page, '@_shi_resizeVar@8');
  await toggleRowByName(page, '@_shi_taskRemovePool@4');

  const diffRows = [
    await getDiffRowByName(page, '@_shi_resizeVar@8'),
    await getDiffRowByName(page, '@_shi_taskRemovePool@4'),
  ];

  // Verify initial state.
  await expect(diffRows[0].getByRole('radio', { name: 'Original' })).toBeChecked();
  await expect(diffRows[1].getByRole('radio', { name: 'Original' })).toBeChecked();

  // Change value in first row.
  await diffRows[0].getByRole('radio', { name: 'Both' }).click();

  // Second row should keep its value
  await expect(diffRows[0].getByRole('radio', { name: 'Original' })).not.toBeChecked();
  await expect(diffRows[1].getByRole('radio', { name: 'Original' })).toBeChecked();

  // Change value in second row
  await diffRows[1].getByRole('radio', { name: 'None' }).click();

  // Each row has its own value.
  await expect(diffRows[0].getByRole('radio', { name: 'Both' })).toBeChecked();
  await expect(diffRows[1].getByRole('radio', { name: 'None' })).toBeChecked();
});
