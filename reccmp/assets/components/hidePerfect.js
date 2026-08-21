/** @import { ReccmpInternalState } from '../types' */

import { ReccmpHidePerfectEvent, ReccmpRegisterEvent } from '../events';

// reccmp-pack-begin
class HidePerfect extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `<label><input type="checkbox" />Hide 100% match</label>`;
    const checkbox = /** @type {HTMLInputElement} */ (this.querySelector('input[type=checkbox]'));
    checkbox.addEventListener('change', (evt) => {
      this.dispatchEvent(new ReccmpHidePerfectEvent(/** @type {HTMLInputElement} */ (evt.target).checked));
    });

    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  /** @param {ReccmpInternalState} state */
  update({ hidePerfect }) {
    const checkbox = /** @type {HTMLInputElement} */ (this.querySelector('input[type=checkbox]'));
    checkbox.checked = hidePerfect;
  }
}

// reccmp-pack-end
export default HidePerfect;
