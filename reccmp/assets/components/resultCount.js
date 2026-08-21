/** @import { ReccmpInternalState } from '../types' */

import { ReccmpRegisterEvent } from '../events';

// reccmp-pack-begin
class ResultCount extends window.HTMLElement {
  connectedCallback() {
    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  /** @param {ReccmpInternalState} state */
  update({ results }) {
    this.textContent = String(results.length);
  }
}

// reccmp-pack-end
export default ResultCount;
