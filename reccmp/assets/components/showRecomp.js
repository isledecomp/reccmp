/** @import { ReccmpInternalState } from '../types' */

import { ReccmpRegisterEvent, ReccmpShowRecompEvent } from '../events';

// reccmp-pack-begin
class ShowRecomp extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `<label><input type="checkbox" />Show recomp address</label>`;
    const checkbox = /** @type {HTMLInputElement} */ (this.querySelector('input[type=checkbox]'));
    checkbox.addEventListener('change', (evt) => {
      this.dispatchEvent(new ReccmpShowRecompEvent(/** @type {HTMLInputElement} */ (evt.target).checked));
    });

    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  /** @param {ReccmpInternalState} state */
  update({ showRecomp }) {
    const checkbox = /** @type {HTMLInputElement} */ (this.querySelector('input[type=checkbox]'));
    checkbox.checked = showRecomp;
  }
}

// reccmp-pack-end
export default ShowRecomp;
