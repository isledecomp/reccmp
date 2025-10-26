import { ReccmpRegisterEvent } from '../events';

// reccmp-pack-begin
class HidePerfect extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `<label><input type="checkbox" />Hide 100% match</label>`;
    this.querySelector('input[type=checkbox]').addEventListener('change', (evt) => {
      this.dispatchEvent(new CustomEvent('setHidePerfect', { bubbles: true, detail: evt.target.checked }));
    });

    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  update({ hidePerfect }) {
    this.querySelector('input[type=checkbox]').checked = hidePerfect;
  }
};

// reccmp-pack-end
export default HidePerfect;
