// reccmp-pack-begin

// Special internal values to ensure this sort order for matching column:
// 1. Stub
// 2. Any match percentage [0.0, 1.0)
// 3. Effective match
// 4. Actual 100% match
function getRowSortValue(row) {
  // Stubs appear at the bottom, below even a 0% match.
  if ('stub' in row) {
    return -1;
  }

  // An effective match sorts near the top
  // but under a non-effective match.
  if ('effective' in row) {
    return 1.0;
  }

  // Boost non-effective match so they appear at the top.
  if (row.matching === 1.0) {
    return 1000;
  }

  return row.matching;
}

function createSortFunction({ sortCol, sortDesc }) {
  return (rowA, rowB) => {
    const valA = sortCol === 'matching' ? getRowSortValue(rowA) : rowA[sortCol];
    const valB = sortCol === 'matching' ? getRowSortValue(rowB) : rowB[sortCol];

    if (valA > valB) {
      return sortDesc ? -1 : 1;
    } else if (valA < valB) {
      return sortDesc ? 1 : -1;
    }

    return 0;
  };
}

function createFilterFunction({ hidePerfect, hideStub, query, filterType }) {
  const queryNormalized = query.toLowerCase().trim();

  return (row) => {
    // Destructuring sets defaults for optional values from this object.
    const { effective = false, stub = false, diff = '', name, address, matching } = row;

    if (hidePerfect && (effective || matching >= 1)) {
      return false;
    }

    if (hideStub && stub) {
      return false;
    }

    if (queryNormalized === '') {
      return true;
    }

    // Name/addr search
    if (filterType === 1) {
      return address.includes(queryNormalized) || name.toLowerCase().includes(queryNormalized);
    }

    // no diff for review.
    if (diff === '') {
      return false;
    }

    // special matcher for combined diff
    const anyLineMatch = ([_addr, line]) => line.toLowerCase().trim().includes(queryNormalized);

    // Flatten all diff groups for the search
    const diffs = diff.flatMap(([_slug, subgroups]) => subgroups);
    for (const subgroup of diffs) {
      const { both = [], orig = [], recomp = [] } = subgroup;

      // If search includes context
      if (filterType === 2 && both.some(anyLineMatch)) {
        return true;
      }

      if (orig.some(anyLineMatch) || recomp.some(anyLineMatch)) {
        return true;
      }
    }

    return false;
  };
}

function batched(input, chunkSize) {
  function* gen(arr, n) {
    for (let i = 0; i < arr.length; i += n) {
      yield arr.slice(i, i + n);
    }
  }

  return [...gen(input, Math.max(1, chunkSize))];
}

class ReccmpState {
  constructor(dataset) {
    this.dataset = dataset;
    this.state = {
      // Filtered list of entities
      results: this.dataset,

      // results split into subarrays according to the pageSize.
      pages: [],

      // Sort column and direction
      sortCol: 'address',
      sortDesc: false,

      // Query text and which fields to search.
      query: '',
      filterType: 1,

      // Row filtering
      hidePerfect: false,
      hideStub: false,

      // Column hiding
      showRecomp: false,

      // Rows with detail row (keyed by address)
      expanded: {},

      // Paging. Numbers are 0-based. Display components add 1 to both for.
      currentPage: [],
      pageNumber: 0,
      maxPageNumber: 0,
      pageSize: 200,
    };

    // Populate fields with default search options.
    this.updateResults();
  }

  clampPage(desiredPage) {
    // Clamp desiredPage to (0, maxPageNumber] --> a page that actually exists.
    return Math.max(0, Math.min(desiredPage, this.state.maxPageNumber));
  }

  updateCurrentPage() {
    // Should be called whenever state.pageNumber changes.
    // If the current search filters yield no results, then there will be no pages
    // so don't try to index the pages array in that case.
    if (this.state.pages.length > 0) {
      this.state.currentPage = this.state.pages[this.state.pageNumber];
    } else {
      this.state.currentPage = [];
    }
  }

  updateResults() {
    const filterFn = createFilterFunction(this.state);
    const sortFn = createSortFunction(this.state);

    this.state.results = this.dataset.filter(filterFn).sort(sortFn);
    this.state.pages = batched(this.state.results, this.state.pageSize);
    this.state.maxPageNumber = Math.max(0, this.state.pages.length - 1);
    this.state.pageNumber = Math.min(this.state.pageNumber, this.state.maxPageNumber);
    this.updateCurrentPage();
  }

  setPageNumber(page) {
    this.state.pageNumber = this.clampPage(page);
    this.updateCurrentPage();
  }

  setFilterType(value) {
    // 1: Search by address or name.
    // 2: Search disassembly.
    // 3: Search disassembly, diff instructions only.
    const filterType = parseInt(value);
    if (filterType >= 1 && filterType <= 3) {
      this.state.filterType = filterType;
    }

    this.updateResults();
  }

  setQuery(query) {
    this.state.query = query;
    this.updateResults();
  }

  setShowRecomp(value) {
    this.state.showRecomp = value;

    // Don't sort by the recomp column we are about to hide
    if (!this.state.showRecomp && this.state.sortCol === 'recomp') {
      this.state.sortCol = 'address';
      // Re-sort using the address column (GH issue #195)
      this.updateResults();
    }
  }

  setSortCol(column) {
    // Flip sort direction if this is the current sort column.
    if (column === this.state.sortCol) {
      this.state.sortDesc = !this.state.sortDesc;
    } else {
      this.state.sortCol = column;
    }
    this.state.sortCol = column;
    this.updateResults();
  }

  setHidePerfect(value) {
    this.state.hidePerfect = value;
    this.updateResults();
  }

  setHideStub(value) {
    this.state.hideStub = value;
    this.updateResults();
  }

  setPageSize(value) {
    this.state.pageSize = parseInt(value);
    this.updateResults();
  }

  toggleExpanded(addr) {
    if (addr in this.state.expanded) {
      delete this.state.expanded[addr];
    } else {
      this.state.expanded[addr] = true;
    }
  }
}

// reccmp-pack-end
export { ReccmpState };
