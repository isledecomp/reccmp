/** @import { ReccmpInternalState } from '../types' */

import { ReccmpFilterTypeEvent, ReccmpRegisterEvent } from '../events';

// reccmp-pack-begin
class SearchOptions extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `
<label><input type="radio" name="filterType" value=1 />Name/address</label>
<label><input type="radio" name="filterType" value=2 />Asm output</label>
<label><input type="radio" name="filterType" value=3 />Asm diffs only</label>`;

    this.querySelectorAll('input[name=filterType]').forEach((element) => {
      const radio = /** @type {HTMLInputElement} */ (element);
      radio.addEventListener('change', () => {
        const value = /** @type {string} */ (radio.getAttribute('value'));
        this.dispatchEvent(new ReccmpFilterTypeEvent(value));
      });
    });

    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  /** @param {ReccmpInternalState} state */
  update({ filterType }) {
    this.querySelectorAll('input[name=filterType]').forEach((element) => {
      const radio = /** @type {HTMLInputElement} */ (element);
      const value = /** @type {string} */ (radio.getAttribute('value'));
      radio.checked = filterType === parseInt(value);
    });
  }
}

// reccmp-pack-end
export default SearchOptions;
