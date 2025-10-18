import { global_reccmp_data } from './globals';
import { ReccmpState } from './state';

// reccmp-pack-begin

class ReccmpProvider extends window.HTMLElement {
  constructor() {
    super();
    this.reccmp = new ReccmpState(global_reccmp_data);
    this.listeners = [];
    this.tables = [];

    this.addEventListener('reccmp-register', (evt) => {
      evt.stopImmediatePropagation();
      this.listeners.push(evt.detail);
      // Call the listener immediately after registering.
      // This populates the component with data.
      evt.detail(this.reccmp.state);
    });

    this.addEventListener('reccmp-table', (evt) => {
      evt.stopImmediatePropagation();
      this.tables.push(evt.detail);
    });

    this.addEventListener('setHidePerfect', (evt) => {
      this.reccmp.setHidePerfect(evt.detail);
      this.callListeners();
    });

    this.addEventListener('setHideStub', (evt) => {
      this.reccmp.setHideStub(evt.detail);
      this.callListeners();
    });

    this.addEventListener('setShowRecomp', (evt) => {
      this.reccmp.setShowRecomp(evt.detail);
      this.callListeners();
    });

    this.addEventListener('prevPage', () => {
      this.reccmp.setPageNumber(this.reccmp.state.pageNumber - 1);
      this.callListeners();
    });

    this.addEventListener('nextPage', () => {
      this.reccmp.setPageNumber(this.reccmp.state.pageNumber + 1);
      this.callListeners();
    });

    this.addEventListener('setPage', (evt) => {
      this.reccmp.setPageNumber(evt.detail);
      this.callListeners();
    });

    this.addEventListener('setQuery', (evt) => {
      this.reccmp.setQuery(evt.detail);
      this.callListeners();
    });

    this.addEventListener('setFilterType', (evt) => {
      this.reccmp.setFilterType(evt.detail);
      this.callListeners();
    });

    this.addEventListener('setSortCol', (evt) => {
      this.reccmp.setSortCol(evt.detail);
      this.callListeners();
    });

    this.addEventListener('setPageSize', (evt) => {
      this.reccmp.setPageSize(evt.detail);
      this.callListeners();
    });

    this.addEventListener('toggleExpanded', (evt) => {
      this.reccmp.toggleExpanded(evt.detail);
      for (const fn of this.tables) {
        fn(this.reccmp.state);
      }
    });
  }

  callListeners() {
    for (const fn of this.listeners) {
      fn(this.reccmp.state);
    }
  }
}

// reccmp-pack-end
export { ReccmpProvider };
