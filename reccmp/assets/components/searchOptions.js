import { ReccmpRegisterEvent } from '../events';

// reccmp-pack-begin
class SearchOptions extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = `
<label><input type="radio" name="filterType" value=1 />Name/address</label>
<label><input type="radio" name="filterType" value=2 />Asm output</label>
<label><input type="radio" name="filterType" value=3 />Asm diffs only</label>`;

    this.querySelectorAll('input[name=filterType]').forEach((radio) => {
      radio.addEventListener('change', () => {
        this.dispatchEvent(new CustomEvent('setFilterType', { bubbles: true, detail: radio.getAttribute('value') }));
      });
    });

    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
  }

  update({ filterType }) {
    this.querySelectorAll('input[name=filterType]').forEach((radio) => {
      const checked = filterType === parseInt(radio.getAttribute('value'));
      radio.checked = checked;
    });
  }
}

// reccmp-pack-end
export default SearchOptions;
