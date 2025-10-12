import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('');
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
