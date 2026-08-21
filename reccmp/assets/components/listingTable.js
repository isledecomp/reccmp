import { ReccmpRegisterEvent, ReccmpSortColEvent, ReccmpTableEvent, ReccmpToggleExpandedEvent } from '../events';

/** @import { ColumnNames, ReccmpComparedEntity, ReccmpInternalState } from '../types' */

// reccmp-pack-begin
/** @param {ReccmpComparedEntity} row */
function countDiffs(row) {
  const { diff = '' } = row;
  if (diff === '') {
    return '';
  }

  const diffs = diff.flatMap(([_slug, subgroups]) => subgroups);
  const diffLength = diffs.filter((d) => !('both' in d)).length;
  const diffWord = diffLength === 1 ? 'diff' : 'diffs';
  return diffLength === 0 ? '' : `${diffLength} ${diffWord}`;
}

/**
 * @param {ReccmpComparedEntity} row
 * @returns {string}
 */
function getMatchPercentText(row) {
  if ('stub' in row) {
    return 'stub';
  }

  if ('effective' in row) {
    return '100.00%*';
  }

  return `${(row.matching * 100).toFixed(2)}%`;
}

/**
 * @param {ReccmpComparedEntity} obj
 * @param {boolean} showRecomp
 * @returns {HTMLTableRowElement}
 */
function createDiffRow(obj, showRecomp) {
  let contents;

  // If "diff" is undefined or empty, that means
  // there are no diffs for this entity. (GH #201)
  const { diff = [], matching = 0.0 } = obj;

  if (diff.length === 0) {
    contents = document.createElement('div');
    contents.className = 'no-diff';
    contents.textContent = matching === 1.0 ? 'Identical function - no diff' : 'No diff available';
  } else {
    contents = document.createElement('diff-display');
    contents.dataset.option = '1';
    contents.dataset.address = obj.address;
  }

  const td = document.createElement('td');
  td.setAttribute('colspan', showRecomp ? '5' : '4');
  td.append(contents);

  const tr = document.createElement('tr');
  tr.dataset.diff = obj.address;
  tr.append(td);
  return tr;
}

/**
 * @param {ReccmpComparedEntity} obj
 * @param {boolean} showRecomp
 * @returns {HTMLTableRowElement}
 */
function createFuncRow(obj, showRecomp) {
  /**
   * @param {string} dataCol
   * @param {boolean} canCopy
   * @param {string} textContent
   * @returns {HTMLTableCellElement}
   */
  const createColumn = (dataCol, canCopy, textContent) => {
    const td = document.createElement('td');
    td.dataset.col = dataCol;
    if (canCopy) {
      const copy = document.createElement('click-to-copy');
      copy.textContent = textContent;
      td.append(copy);
    } else {
      td.append(textContent);
    }

    return td;
  };

  const cols = {
    address: createColumn('address', true, obj.address),
    ...(showRecomp && { recomp: createColumn('recomp', true, obj.recomp) }),
    name: createColumn('name', false, obj.name),
    diffs: createColumn('diffs', false, countDiffs(obj)),
    matching: createColumn('matching', false, getMatchPercentText(obj)),
  };

  const tr = document.createElement('tr');
  tr.dataset.address = obj.address;
  tr.append(...Object.values(cols));
  return tr;
}

/**
 * @param {boolean} showRecomp
 * @param {ColumnNames} sortCol
 * @param {boolean} sortDesc
 * @returns {HTMLTableRowElement}
 */
function createHeaderRow(showRecomp, sortCol, sortDesc) {
  const cols = {
    address: 'Address',
    ...(showRecomp && { recomp: 'Recomp' }),
    name: 'Name',
    diffs: '',
    matching: 'Matching',
  };

  const headers = Object.entries(cols).map(([key, name]) => {
    if (key === 'diffs') {
      /** @type {HTMLTableCellElement} */
      const th = document.createElement('th');
      th.dataset.col = 'diffs';
      th.dataset.noSort = 'true';
      return th;
    }

    const sort_indicator = document.createElement('div');
    if (key === sortCol) {
      sort_indicator.innerHTML = sortDesc ? '&#9660' : '&#9650';
    }

    /** @type {HTMLTableCellElement} */
    const th = document.createElement('th');
    th.dataset.col = key;
    const div = document.createElement('div');
    const span = document.createElement('span');
    span.textContent = name;
    div.append(span, sort_indicator);
    th.append(div);
    return th;
  });

  const tr = document.createElement('tr');
  tr.append(...headers);
  return tr;
}

class ListingTable extends window.HTMLElement {
  connectedCallback() {
    this.innerHTML = '<table id="listing"><thead></thead><tbody></tbody></table>';

    this.dispatchEvent(new ReccmpRegisterEvent(this.update.bind(this)));
    this.dispatchEvent(new ReccmpTableEvent(this.setDiffRow.bind(this)));
  }

  /** @param {ReccmpInternalState} state */
  update({ currentPage, expanded, showRecomp, sortCol, sortDesc }) {
    const header_row = createHeaderRow(showRecomp, sortCol, sortDesc);

    const rows = [];

    // Create rows for this page.
    for (const obj of currentPage) {
      rows.push(createFuncRow(obj, showRecomp));
      if (obj.address in expanded) {
        rows.push(createDiffRow(obj, showRecomp));
      }
    }

    const thead = /** @type {HTMLTableSectionElement } */ (this.querySelector('thead'));
    const tbody = /** @type {HTMLTableSectionElement } */ (this.querySelector('tbody'));

    thead.replaceChildren(header_row);
    tbody.replaceChildren(...rows);

    this.querySelectorAll('th:not([data-no-sort])').forEach((element) => {
      const th = /** @type {HTMLTableCellElement} */ (element);
      const col = /** @type {ColumnNames} */ (th.dataset.col);
      if (col) {
        const span = th.querySelector('span');
        if (span) {
          span.addEventListener('click', () => {
            this.dispatchEvent(new ReccmpSortColEvent(col));
          });
        }
      }
    });

    this.querySelectorAll('tr[data-address]').forEach((element) => {
      const row = /** @type {HTMLTableRowElement} */ (element);
      // Clicking the name column toggles the diff detail row.
      // This is added or removed without replacing the entire <tbody>.
      const cell = /** @type {HTMLTableCellElement} */ (row.querySelector('td[data-col="name"]'));
      cell.addEventListener('click', () => {
        this.dispatchEvent(new ReccmpToggleExpandedEvent(row.dataset.address ?? ''));
      });
    });
  }

  /** @param {ReccmpInternalState} state */
  setDiffRow({ currentPage, expanded, showRecomp }) {
    const tbody = /** @type {HTMLTableSectionElement} */ (this.querySelector('tbody'));

    for (const obj of currentPage) {
      const address = obj.address;
      const funcrow = /** @type {HTMLTableRowElement} */ (tbody.querySelector(`tr[data-address="${address}"]`));
      if (funcrow === null) {
        continue;
      }

      const existing = /** @type {HTMLTableRowElement} */ (tbody.querySelector(`tr[data-diff="${address}"]`));
      const isExpanded = existing !== null;
      const shouldExpand = address in expanded;

      if (!isExpanded && shouldExpand) {
        // Insert the diff row after the parent func row.
        funcrow.insertAdjacentElement('afterend', createDiffRow(obj, showRecomp));
      } else if (isExpanded && !shouldExpand) {
        tbody.removeChild(existing);
      }
    }
  }
}

// reccmp-pack-end
export { ListingTable, getMatchPercentText };
