import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('');
});

test.describe('Table display options', () => {
  test('Hide 100%', async ({ page }) => {
    // TODO: Should use 'cell' role
    const matched = page.getByRole('table').getByText('100.00%');

    // Make sure we have a row with 100% on the current page.
    await expect(matched).not.toHaveCount(0);

    // Check the box to hide 100% rows
    const checkbox = page.getByRole('checkbox', { name: /Hide 100%/ });
    await checkbox.click();
    await expect(checkbox).toBeChecked();

    // Make sure the 100% rows are gone.
    await expect(matched).toHaveCount(0);

    // Uncheck the box.
    await checkbox.click();
    await expect(checkbox).not.toBeChecked();

    // The rows should return.
    await expect(matched).not.toHaveCount(0);
  });

  test('Hide stubs', async ({ page }) => {
    // TODO: Should use 'cell' role
    const stubs = page.getByRole('table').getByText('stub').filter();

    // Make sure we have a stub on the current page.
    await expect(stubs).not.toHaveCount(0);

    // Check the box to hide 100% rows
    const checkbox = page.getByRole('checkbox', { name: /Hide stubs/ });
    await checkbox.click();
    await expect(checkbox).toBeChecked();

    // Make sure the stubs are gone.
    await expect(stubs).toHaveCount(0);

    // Uncheck the box.
    await checkbox.click();
    await expect(checkbox).not.toBeChecked();

    // The rows should return.
    await expect(stubs).not.toHaveCount(0);
  });

  test('Show recomp', async ({ page }) => {
    // TODO: columnheader role?
    const recompHeader = page.getByRole('rowgroup').getByText(/Recomp/);

    // Recomp header is not displayed at the start.
    await expect(recompHeader).not.toBeVisible();

    // Check the box to display the recomp column.
    const checkbox = page.getByRole('checkbox', { name: /Show recomp/ });
    await checkbox.click();
    await expect(checkbox).toBeChecked();

    // Should now see the column header.
    await expect(recompHeader).toBeVisible();

    // Uncheck the box.
    await checkbox.click();
    await expect(checkbox).not.toBeChecked();

    // Recomp header is gone.
    await expect(recompHeader).not.toBeVisible();

    // TODO: not inspecting column data. Should we do that?
  });
});

test.describe('Pagination', () => {
  const PAGE_SIZE = 200; // defined in reccmp.js

  // Returns integer from results counter.
  const getResultCount = async (page) => {
    const resultsText = await page.getByText(/Results: \d+/).textContent();
    const [count] = resultsText.match(/\d+/);
    return parseInt(count);
  };

  // Returns integers from 'Page x of y' display.
  const getPageNumbers = async (page) => {
    const pageText = await page.getByText(/Page \d+ of \d+/).textContent();
    const [start, end] = pageText.match(/\d+/g);
    return [parseInt(start), parseInt(end)];
  };

  test('Accurate page count', async ({ page }) => {
    // Derive the max page count based on the number of entities.
    // This assumes that no entities are hidden on startup.
    // We could also just hardcode this value.
    const count = await getResultCount(page);
    const [start, end] = await getPageNumbers(page);

    expect(start).toEqual(1);
    expect(end).toEqual(Math.ceil(count / PAGE_SIZE));
  });

  test('Disable buttons at page limit', async ({ page }) => {
    // This requires us to have at least two pages worth of entities.
    const btnPrev = page.getByRole('button').getByText(/prev/);
    const btnNext = page.getByRole('button').getByText(/next/);

    // Prev button should be disabled on page one.
    await expect(btnPrev).toBeDisabled();
    await expect(btnNext).not.toBeDisabled();

    // Click through to the last page.
    const [start, end] = await getPageNumbers(page);
    for (let i = start; i < end; i++) {
      await btnNext.click();
    }

    // Disable Next button when we reach the final page.
    await expect(btnPrev).not.toBeDisabled();
    await expect(btnNext).toBeDisabled();
  });

  test('Update page display with button clicks', async ({ page }) => {
    const btnPrev = page.getByRole('button').getByText(/prev/);
    const btnNext = page.getByRole('button').getByText(/next/);

    // Destructuring only the first index
    let [pageNumber] = await getPageNumbers(page);
    expect(pageNumber).toEqual(1);

    // Go to page 2
    await btnNext.click();
    [pageNumber] = await getPageNumbers(page);
    expect(pageNumber).toEqual(2);

    // Go back to page 1
    await btnPrev.click();
    [pageNumber] = await getPageNumbers(page);
    expect(pageNumber).toEqual(1);
  });

  test('Update page count after filtering', async ({ page }) => {
    const btnNext = page.getByRole('button').getByText(/next/);

    // Make sure we have more than one page.
    await expect(btnNext).not.toBeDisabled();

    // Filter results using something we know matches fewer than PAGE_SIZE entities.
    await page.getByRole('searchbox').fill('IsleApp');

    // We should be on page 1 of 1.
    await expect(btnNext).toBeDisabled();
    const [start, end] = await getPageNumbers(page);
    expect(start).toEqual(1);
    expect(end).toEqual(1);
  });

  test('Change page if the one we are on no longer exists', async ({ page }) => {
    // Change the page and make sure we are on page 2.
    await page.getByRole('button').getByText(/next/).click();
    let [pageNumber] = await getPageNumbers(page);
    expect(pageNumber).toEqual(2);

    // Filter results using something we know matches fewer than PAGE_SIZE entities.
    await page.getByRole('searchbox').fill('IsleApp');

    // We should be sent back to page 1, the only page.
    [pageNumber] = await getPageNumbers(page);
    expect(pageNumber).toEqual(1);

    // Clear the filter and restore the full dataset.
    await page.getByRole('searchbox').clear();

    // Don't change the page back to 2.
    [pageNumber] = await getPageNumbers(page);
    expect(pageNumber).toEqual(1);
  });
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

test.describe('Search bar', () => {
  test('Search by name', async ({ page }) => {
    const query = 'IsleApp';
    const searchbox = page.getByRole('searchbox');

    // Locators for rows matching and not matching our intended query.
    // TODO: use better locator for table rows/cells
    const notMatchRows = page.locator('func-row').filter({ hasNotText: query });
    const matchRows = page.locator('func-row').filter({ hasText: query });

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
    const rows = page.locator('func-row');

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
    const rows = page.locator('func-row');

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
