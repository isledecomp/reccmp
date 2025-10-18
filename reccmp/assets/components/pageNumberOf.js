import { ReccmpRegisterEvent } from '../events';

// reccmp-pack-begin
class PageNumberOf extends window.HTMLElement {
  connectedCallback() {
    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  update({ pageNumber, maxPageNumber }) {
    this.textContent = `Page ${pageNumber + 1} of ${maxPageNumber + 1}`
  }
};

// reccmp-pack-end
export default PageNumberOf;
