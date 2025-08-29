import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('');
});

test('Entity names with HTML-escaped characters', async ({ page }) => {
  // Rows in the table with characters that should be escaped for XML/HTML should appear correctly.
  // For example: <, >, and &.
  // These test cases should be on the first page and visible right away.
  await expect(page.locator('tr[data-address]').getByText('Vector2::MulImpl(float const &)')).toBeAttached();
  await expect(page.locator('tr[data-address]').getByText('list<ROI *,allocator<ROI *> >::_Buynode')).toBeAttached();
  await expect(page.locator('tr[data-address]').getByText("MxParam::`scalar deleting destructor'")).toBeAttached();
});
