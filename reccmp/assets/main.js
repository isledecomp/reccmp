import ClickToCopy from './components/clickToCopy';
import { DiffDisplay, DiffDisplayOptions } from './components/diffDisplay';
import HidePerfect from './components/hidePerfect';
import HideStub from './components/hideStub';
import ListingTable from './components/listingTable';
import NextPageButton from './components/nextPageButton';
import PageNumberOf from './components/pageNumberOf';
import PageSelect from './components/pageSelect';
import PrevPageButton from './components/prevPageButton';
import ResultCount from './components/resultCount';
import SearchBar from './components/searchbar';
import SearchOptions from './components/searchOptions';
import ShowRecomp from './components/showRecomp';
import { ReccmpProvider } from './provider';

// reccmp-pack-begin
window.onload = () => {
  window.customElements.define('reccmp-provider', ReccmpProvider);
  window.customElements.define('click-to-copy', ClickToCopy); // used by listing-table
  window.customElements.define('listing-table', ListingTable);
  window.customElements.define('diff-display', DiffDisplay);
  window.customElements.define('diff-display-options', DiffDisplayOptions);
  window.customElements.define('search-bar', SearchBar);
  window.customElements.define('hide-perfect', HidePerfect);
  window.customElements.define('hide-stub', HideStub);
  window.customElements.define('next-page-button', NextPageButton);
  window.customElements.define('prev-page-button', PrevPageButton);
  window.customElements.define('result-count', ResultCount);
  window.customElements.define('search-options', SearchOptions);
  window.customElements.define('show-recomp', ShowRecomp);
  window.customElements.define('page-number-of', PageNumberOf);
  window.customElements.define('page-select', PageSelect);
};
