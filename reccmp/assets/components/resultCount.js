import { ReccmpRegisterEvent } from '../events';

// reccmp-pack-begin
class ResultCount extends window.HTMLElement {
  connectedCallback() {
    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  update({ results }) {
    this.textContent = results.length;
  }
}

// reccmp-pack-end
export default ResultCount;
