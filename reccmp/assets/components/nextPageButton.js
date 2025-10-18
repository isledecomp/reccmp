import { ReccmpRegisterEvent } from '../events';

// reccmp-pack-begin
class NextPageButton extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `<button>next</button>`;
    this.querySelector('button').addEventListener('click', () => {
      this.dispatchEvent(new CustomEvent('nextPage', { bubbles: true }));
    });

    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  update({ pageNumber, maxPageNumber }) {
    const button = this.querySelector('button');
    if (pageNumber === maxPageNumber) {
      button.setAttribute('disabled', '');
    } else {
      button.removeAttribute('disabled');
    }
  }
};

// reccmp-pack-end
export default NextPageButton;
