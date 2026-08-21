/** @import { ReccmpInternalState } from '../types' */

import { ReccmpNextPageEvent, ReccmpRegisterEvent } from '../events';

// reccmp-pack-begin
class NextPageButton extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `<button>next</button>`;
    const button = /** @type {HTMLButtonElement} */ (this.querySelector('button'));
    button.addEventListener('click', () => {
      this.dispatchEvent(new ReccmpNextPageEvent());
    });

    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  /** @param {ReccmpInternalState} state */
  update({ pageNumber, maxPageNumber }) {
    const button = /** @type {HTMLButtonElement} */ (this.querySelector('button'));
    if (pageNumber === maxPageNumber) {
      button.setAttribute('disabled', '');
    } else {
      button.removeAttribute('disabled');
    }
  }
}

// reccmp-pack-end
export default NextPageButton;
