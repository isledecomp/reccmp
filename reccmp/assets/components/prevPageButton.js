/** @import { ReccmpInternalState } from '../types' */

import { ReccmpPrevPageEvent, ReccmpRegisterEvent } from '../events';

// reccmp-pack-begin
class PrevPageButton extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `<button>prev</button>`;
    const button = /** @type {HTMLButtonElement} */ (this.querySelector('button'));
    button.addEventListener('click', () => {
      this.dispatchEvent(new ReccmpPrevPageEvent());
    });

    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  /** @param {ReccmpInternalState} state */
  update({ pageNumber }) {
    const button = /** @type {HTMLButtonElement} */ (this.querySelector('button'));
    if (pageNumber === 0) {
      button.setAttribute('disabled', '');
    } else {
      button.removeAttribute('disabled');
    }
  }
}

// reccmp-pack-end
export default PrevPageButton;
