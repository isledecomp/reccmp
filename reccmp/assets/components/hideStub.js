import { ReccmpRegisterEvent } from '../events';

// reccmp-pack-begin
class HideStub extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `<label><input type="checkbox" />Hide stubs</label>`;
    this.querySelector('input[type=checkbox]').addEventListener('change', (evt) => {
      this.dispatchEvent(new CustomEvent('setHideStub', { bubbles: true, detail: evt.target.checked }));
    });

    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  update({ hideStub }) {
    this.querySelector('input[type=checkbox]').checked = hideStub;
  }
}

// reccmp-pack-end
export default HideStub;
