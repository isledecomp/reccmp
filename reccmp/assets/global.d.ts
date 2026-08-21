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

declare global {
  interface HTMLElementEventMap {
    [ReccmpRegisterEvent.eventName]: ReccmpRegisterEvent;
    [ReccmpTableEvent.eventName]: ReccmpTableEvent;
    [ReccmpSetPageEvent.eventName]: ReccmpSetPageEvent;
    [ReccmpQueryEvent.eventName]: ReccmpQueryEvent;
    [ReccmpFilterTypeEvent.eventName]: ReccmpFilterTypeEvent;
    [ReccmpHidePerfectEvent.eventName]: ReccmpHidePerfectEvent;
    [ReccmpHideStubEvent.eventName]: ReccmpHideStubEvent;
    [ReccmpShowRecompEvent.eventName]: ReccmpShowRecompEvent;
    [ReccmpPrevPageEvent.eventName]: ReccmpPrevPageEvent;
    [ReccmpNextPageEvent.eventName]: ReccmpNextPageEvent;
    [ReccmpSortColEvent.eventName]: ReccmpSortColEvent;
    [ReccmpPageSizeEvent.eventName]: ReccmpPageSizeEvent;
    [ReccmpToggleExpandedEvent.eventName]: ReccmpToggleExpandedEvent;
  }
}
