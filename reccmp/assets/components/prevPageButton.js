import { ReccmpRegisterEvent } from '../events';

// reccmp-pack-begin
class PrevPageButton extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `<button>prev</button>`;
    this.querySelector('button').addEventListener('click', () => {
      this.dispatchEvent(new CustomEvent('prevPage', { bubbles: true }));
    });

    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  update({ pageNumber }) {
    const button = this.querySelector('button');
    if (pageNumber === 0) {
      button.setAttribute('disabled', '');
    } else {
      button.removeAttribute('disabled');
    }
  }
};

// reccmp-pack-end
export default PrevPageButton;
