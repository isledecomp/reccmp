/** @import { ReccmpInternalState } from '../types' */

import { ReccmpHideStubEvent, ReccmpRegisterEvent } from '../events';

// reccmp-pack-begin
class HideStub extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `<label><input type="checkbox" />Hide stubs</label>`;
    const checkbox = /** @type {HTMLInputElement} */ (this.querySelector('input[type=checkbox]'));
    checkbox.addEventListener('change', (evt) => {
      this.dispatchEvent(new ReccmpHideStubEvent(/** @type {HTMLInputElement} */ (evt.target).checked));
    });

    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  /** @param {ReccmpInternalState} state */
  update({ hideStub }) {
    const checkbox = /** @type {HTMLInputElement} */ (this.querySelector('input[type=checkbox]'));
    checkbox.checked = hideStub;
  }
}

// reccmp-pack-end
export default HideStub;
