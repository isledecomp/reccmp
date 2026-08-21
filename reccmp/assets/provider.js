/** @import { InternalStateCallback } from './types' */

import {
  ReccmpFilterTypeEvent,
  ReccmpHidePerfectEvent,
  ReccmpHideStubEvent,
  ReccmpNextPageEvent,
  ReccmpPageSizeEvent,
  ReccmpPrevPageEvent,
  ReccmpQueryEvent,
  ReccmpRegisterEvent,
  ReccmpSetPageEvent,
  ReccmpShowRecompEvent,
  ReccmpSortColEvent,
  ReccmpTableEvent,
  ReccmpToggleExpandedEvent,
} from './events';
import { global_reccmp_data } from './globals';
import { ReccmpState } from './state';

// reccmp-pack-begin

class ReccmpProvider extends window.HTMLElement {
  constructor() {
    super();
    /** @type {ReccmpState} */
    this.reccmp = new ReccmpState(global_reccmp_data);
    /** @type {InternalStateCallback[]} */
    this.listeners = [];
    /** @type {InternalStateCallback[]} */
    this.tables = [];

    this.addEventListener(ReccmpRegisterEvent.eventName, (evt) => {
      evt.stopImmediatePropagation();
      this.listeners.push(evt.callback);
      // Call the listener immediately after registering.
      // This populates the component with data.
      evt.callback(this.reccmp.state);
    });

    this.addEventListener(ReccmpTableEvent.eventName, (evt) => {
      evt.stopImmediatePropagation();
      this.tables.push(evt.callback);
    });

    this.addEventListener(ReccmpHidePerfectEvent.eventName, (evt) => {
      this.reccmp.setHidePerfect(evt.value);
      this.callListeners();
    });

    this.addEventListener(ReccmpHideStubEvent.eventName, (evt) => {
      this.reccmp.setHideStub(evt.value);
      this.callListeners();
    });

    this.addEventListener(ReccmpShowRecompEvent.eventName, (evt) => {
      this.reccmp.setShowRecomp(evt.value);
      this.callListeners();
    });

    this.addEventListener(ReccmpPrevPageEvent.eventName, () => {
      this.reccmp.setPageNumber(this.reccmp.state.pageNumber - 1);
      this.callListeners();
    });

    this.addEventListener(ReccmpNextPageEvent.eventName, () => {
      this.reccmp.setPageNumber(this.reccmp.state.pageNumber + 1);
      this.callListeners();
    });

    this.addEventListener(ReccmpSetPageEvent.eventName, (evt) => {
      this.reccmp.setPageNumber(evt.value);
      this.callListeners();
    });

    this.addEventListener(ReccmpQueryEvent.eventName, (evt) => {
      this.reccmp.setQuery(evt.value);
      this.callListeners();
    });

    this.addEventListener(ReccmpFilterTypeEvent.eventName, (evt) => {
      this.reccmp.setFilterType(evt.value);
      this.callListeners();
    });

    this.addEventListener(ReccmpSortColEvent.eventName, (evt) => {
      this.reccmp.setSortCol(evt.value);
      this.callListeners();
    });

    this.addEventListener(ReccmpPageSizeEvent.eventName, (evt) => {
      this.reccmp.setPageSize(evt.value);
      this.callListeners();
    });

    this.addEventListener(ReccmpToggleExpandedEvent.eventName, (evt) => {
      this.reccmp.toggleExpanded(evt.value);
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
