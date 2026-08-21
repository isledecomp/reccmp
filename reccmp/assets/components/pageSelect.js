/** @import { ColumnNames, ReccmpComparedEntity, ReccmpInternalState } from '../types' */

import { ReccmpRegisterEvent, ReccmpSetPageEvent } from '../events';
import { getMatchPercentText } from './listingTable';

// reccmp-pack-begin

/**
 * @param {string} str
 * @returns {string}
 */
function getCppClass(str) {
  const idx = str.indexOf('::');
  if (idx !== -1) {
    return str.slice(0, idx);
  }

  return str;
}

/**
 * Clamp string length to specified length and pad with ellipsis
 * @param {string} str
 * @param {number} maxlen
 * @returns {string}
 */
function stringTruncate(str, maxlen = 20) {
  str = getCppClass(str);
  if (str.length > maxlen) {
    return `${str.slice(0, maxlen)}...`;
  }

  return str;
}

/**
 * @param {ReccmpComparedEntity[][]} pages
 * @param {ColumnNames} sortCol
 * @returns {[number, string, string][]}
 */
function pageHeadings(pages, sortCol) {
  return pages.map((page, index) => {
    const first = page[0];
    const last = page[page.length - 1];

    let start = String(first[sortCol]);
    let end = String(last[sortCol]);

    if (sortCol === 'matching') {
      start = getMatchPercentText(first);
      end = getMatchPercentText(last);
    }

    return [index, stringTruncate(start), stringTruncate(end)];
  });
}

class PageSelect extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `<select></select>`;
    const select = /** @type {HTMLSelectElement} */ (this.querySelector('select'));
    select.addEventListener('change', (evt) => {
      const target = /** @type {HTMLSelectElement} */ (evt.target);
      this.dispatchEvent(new ReccmpSetPageEvent(parseInt(target.value)));
    });

    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  /** @param {ReccmpInternalState} state */
  update({ pages, pageNumber, results, sortCol }) {
    const select = /** @type {HTMLSelectElement} */ (this.querySelector('select'));

    if (results.length === 0) {
      select.setAttribute('disabled', '');
      const option = document.createElement('option');
      option.textContent = '- no results -';
      select.replaceChildren(option);
      return;
    }

    select.removeAttribute('disabled');

    const options = [];
    for (const [value, fromText, toText] of pageHeadings(pages, sortCol)) {
      const option = document.createElement('option');
      option.value = String(value);
      if (pageNumber === value) {
        option.setAttribute('selected', '');
      }
      option.textContent = `${sortCol}: ${fromText} to ${toText}`;
      options.push(option);
    }

    select.replaceChildren(...options);
  }
}

// reccmp-pack-end
export default PageSelect;
