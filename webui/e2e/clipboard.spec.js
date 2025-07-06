import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('');
});

test.describe('Clipboard', () => {
  test('Copy original addr', async ({ page, browserName, context }) => {
    if (browserName === 'chromium') {
      await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    } else if (browserName === 'webkit') {
      test.fixme('Permissions problem using clipboard API outside of user event');
    }

    // The text we want copied.
    const addr = '0x401000';

    // TODO: this is a convoluted way to avoid other page elements
    await page.getByText(addr, { exact: true }).filter({ visible: true }).click();

    // Get the value from the clipboard and confirm that it matches the address.
    const handle = await page.evaluateHandle(() => navigator.clipboard.readText());
    const clipboardContent = await handle.jsonValue();
    expect(clipboardContent).toEqual(addr);
  });
});
