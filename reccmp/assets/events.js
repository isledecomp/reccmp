/** @import { ColumnNames, InternalStateCallback } from './types' */

// reccmp-pack-begin

class ReccmpRegisterEvent extends Event {
  /** @readonly */
  static eventName = 'reccmp-register';
  /** @param {InternalStateCallback} callback */
  constructor(callback) {
    super(ReccmpRegisterEvent.eventName, { bubbles: true, composed: true });
    this.callback = callback;
  }
}

class ReccmpTableEvent extends Event {
  /** @readonly */
  static eventName = 'reccmp-table';
  /** @param {InternalStateCallback} callback */
  constructor(callback) {
    super(ReccmpTableEvent.eventName, { bubbles: true, composed: true });
    this.callback = callback;
  }
}

class ReccmpSetPageEvent extends Event {
  /** @readonly */
  static eventName = 'setPage';
  /** @param {number} value */
  constructor(value) {
    super(ReccmpSetPageEvent.eventName, { bubbles: true, composed: true });
    this.value = value;
  }
}

class ReccmpQueryEvent extends Event {
  /** @readonly */
  static eventName = 'setQuery';
  /** @param {string} value */
  constructor(value) {
    super(ReccmpQueryEvent.eventName, { bubbles: true, composed: true });
    this.value = value;
  }
}

class ReccmpFilterTypeEvent extends Event {
  /** @readonly */
  static eventName = 'setFilterType';
  /** @param {string} value */
  constructor(value) {
    super(ReccmpFilterTypeEvent.eventName, { bubbles: true, composed: true });
    this.value = value;
  }
}

class ReccmpHidePerfectEvent extends Event {
  /** @readonly */
  static eventName = 'setHidePerfect';
  /** @param {boolean} value */
  constructor(value) {
    super(ReccmpHidePerfectEvent.eventName, { bubbles: true, composed: true });
    this.value = value;
  }
}

class ReccmpHideStubEvent extends Event {
  /** @readonly */
  static eventName = 'setHideStub';
  /** @param {boolean} value */
  constructor(value) {
    super(ReccmpHideStubEvent.eventName, { bubbles: true, composed: true });
    this.value = value;
  }
}

class ReccmpShowRecompEvent extends Event {
  /** @readonly */
  static eventName = 'setShowRecomp';
  /** @param {boolean} value */
  constructor(value) {
    super(ReccmpShowRecompEvent.eventName, { bubbles: true, composed: true });
    this.value = value;
  }
}

class ReccmpPrevPageEvent extends Event {
  /** @readonly */
  static eventName = 'prevPage';
  constructor() {
    super(ReccmpPrevPageEvent.eventName, { bubbles: true, composed: true });
  }
}

class ReccmpNextPageEvent extends Event {
  /** @readonly */
  static eventName = 'nextPage';
  constructor() {
    super(ReccmpNextPageEvent.eventName, { bubbles: true, composed: true });
  }
}

class ReccmpSortColEvent extends Event {
  /** @readonly */
  static eventName = 'setSortCol';
  /** @param {ColumnNames} value */
  constructor(value) {
    super(ReccmpSortColEvent.eventName, { bubbles: true, composed: true });
    this.value = value;
  }
}

class ReccmpPageSizeEvent extends Event {
  /** @readonly */
  static eventName = 'setPageSize';
  /** @param {string} value */
  constructor(value) {
    super(ReccmpPageSizeEvent.eventName, { bubbles: true, composed: true });
    this.value = value;
  }
}

class ReccmpToggleExpandedEvent extends Event {
  /** @readonly */
  static eventName = 'toggleExpanded';
  /** @param {string} value */
  constructor(value) {
    super(ReccmpToggleExpandedEvent.eventName, { bubbles: true, composed: true });
    this.value = value;
  }
}

// reccmp-pack-end

export {
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
};
