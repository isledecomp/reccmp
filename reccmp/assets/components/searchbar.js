/** @import { ReccmpInternalState } from '../types' */

import { ReccmpQueryEvent, ReccmpRegisterEvent } from '../events';

// reccmp-pack-begin
class SearchBar extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `<input type="search"></input>`;
    const input = /** @type {HTMLInputElement} */ (this.querySelector('input[type=search]'));
    input.addEventListener('input', (evt) => {
      this.dispatchEvent(new ReccmpQueryEvent(/** @type {HTMLInputElement} */ (evt.target).value));
    });

    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  /** @param {ReccmpInternalState} state */
  update({ query, filterType }) {
    const input = /** @type {HTMLInputElement} */ (this.querySelector('input[type=search]'));
    input.value = query;
    input.placeholder = filterType === 1 ? 'Search for offset or function name...' : 'Search for instruction...';
  }
}
// reccmp-pack-end

export default SearchBar;
