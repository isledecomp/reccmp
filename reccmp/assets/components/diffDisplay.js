/**
 * @import {
 *   DiffFragBoth,
 *   DiffFragSingle,
 *   ReccmpComparedEntity,
 *   ColumnNames,
 *   MatchingOrMismatchingBlock
 * } from "../types"
 *
 */

import { getDataByAddr } from '../globals';

// reccmp-pack-begin

/** @param {MatchingOrMismatchingBlock[]} entries */
function formatAsm(entries) {
  /** @type {HTMLTableRowElement[]} */
  const output = [];

  /**
   * @param {string} text
   * @returns {HTMLTableCellElement}
   */
  const createTh = (text) => {
    const th = document.createElement('th');
    th.innerText = text;
    return th;
  };

  /**
   * @param {string} text
   * @param {string} className
   * @returns {HTMLTableCellElement}
   */
  const createTd = (text, className = '') => {
    const td = document.createElement('td');
    td.innerText = text;
    td.className = className;
    return td;
  };

  entries.forEach((obj) => {
    // These won't all be present. You get "both" for an equal node
    // and orig/recomp for a diff.
    const { both = [], orig = [], recomp = [] } = obj;

    output.push(
      ...both.map(([addr, line, recompAddr]) => {
        const tr = document.createElement('tr');
        tr.appendChild(createTh(addr));
        tr.appendChild(createTh(recompAddr));
        tr.appendChild(createTd(line));
        return tr;
      }),
    );

    output.push(
      ...orig.map(([addr, line]) => {
        const tr = document.createElement('tr');
        tr.appendChild(createTh(addr));
        tr.appendChild(createTh(''));
        tr.appendChild(createTd(`-${line}`, 'diffneg'));
        return tr;
      }),
    );

    output.push(
      ...recomp.map(([addr, line]) => {
        const tr = document.createElement('tr');
        tr.appendChild(createTh(''));
        tr.appendChild(createTh(addr));
        tr.appendChild(createTd(`+${line}`, 'diffpos'));
        return tr;
      }),
    );
  });

  return output;
}

class DiffDisplayOptions extends window.HTMLElement {
  static observedAttributes = ['data-option'];

  connectedCallback() {
    if (this.shadowRoot !== null) {
      return;
    }

    const shadow = this.attachShadow({ mode: 'open' });
    shadow.innerHTML = `
      <style>
        fieldset {
          align-items: center;
          display: flex;
          margin-bottom: 20px;
        }

        label {
          margin-right: 10px;
          user-select: none;
        }

        label, input {
          cursor: pointer;
        }
      </style>
      <fieldset>
        <legend>Address display:</legend>
        <input type="radio" id="showNone" name="addrDisplay" value=0>
        <label for="showNone">None</label>
        <input type="radio" id="showOrig" name="addrDisplay" value=1>
        <label for="showOrig">Original</label>
        <input type="radio" id="showBoth" name="addrDisplay" value=2>
        <label for="showBoth">Both</label>
      </fieldset>`;

    shadow.querySelectorAll('input[type=radio]').forEach((element) => {
      const radio = /** @type {HTMLInputElement} */ (element);
      radio.checked = this.option === radio.getAttribute('value');

      radio.addEventListener('change', (evt) => {
        this.option = /** @type {HTMLInputElement} */ (evt.target).value;
      });
    });
  }

  set option(value) {
    this.setAttribute('data-option', value);
  }

  get option() {
    return this.getAttribute('data-option') ?? '1';
  }

  /** @param {string} name */
  attributeChangedCallback(name) {
    if (name !== 'data-option') {
      return;
    }

    this.dispatchEvent(new Event('change'));
  }
}

class DiffDisplay extends window.HTMLElement {
  static observedAttributes = ['data-option'];

  connectedCallback() {
    if (this.querySelector('diff-display-options') !== null) {
      return;
    }

    const optControl = new DiffDisplayOptions();
    optControl.option = this.option;
    optControl.addEventListener('change', (evt) => {
      this.option = /** @type {DiffDisplayOptions} */ (evt.target).option;
    });
    this.appendChild(optControl);

    const div = document.createElement('div');
    const obj = getDataByAddr(this.address);

    /**
     * @param {string} text
     * @param {string} className
     */
    const createHeaderLine = (text, className) => {
      const div = document.createElement('div');
      div.textContent = text;
      div.className = className;
      return div;
    };

    const groups = obj.diff ?? [];
    groups.forEach(([slug, subgroups]) => {
      const secondTable = document.createElement('table');
      secondTable.classList.add('diffTable');

      const hdr = document.createElement('div');
      hdr.appendChild(createHeaderLine('---', 'diffneg'));
      hdr.appendChild(createHeaderLine('+++', 'diffpos'));
      hdr.appendChild(createHeaderLine(slug, 'diffslug'));
      div.appendChild(hdr);

      const tbody = document.createElement('tbody');
      secondTable.appendChild(tbody);

      const diffs = formatAsm(subgroups);
      for (const el of diffs) {
        tbody.appendChild(el);
      }

      div.appendChild(secondTable);
    });

    this.appendChild(div);
  }

  get address() {
    return this.getAttribute('data-address') ?? ''; // required?
  }

  set address(value) {
    this.setAttribute('data-address', value);
  }

  get option() {
    return this.getAttribute('data-option') ?? '1';
  }

  set option(value) {
    this.setAttribute('data-option', value);
  }
}
// reccmp-pack-end

export { DiffDisplay, DiffDisplayOptions };
