export type DiffFragBoth = [orig_addr: string, instruction: string, recomp_addr: string];
export type DiffFragSingle = [addr: string, instruction: string];

export interface MatchingOrMismatchingBlock {
  both?: DiffFragBoth[];
  orig?: DiffFragSingle[];
  recomp?: DiffFragSingle[];
}

export type UnifiedDiffGroup = [slug: string, groups: MatchingOrMismatchingBlock[]];

export interface ReccmpComparedEntity {
  address: string;
  matching: number;
  name: string;
  recomp: string;
  effective?: boolean;
  stub?: boolean;
  diff?: UnifiedDiffGroup[];
  /* dynamic property access */
  key?: Record<ColumnNames, string | number | boolean>;
}

// Not using "keyof ReccmpComparedEntity" because that includes optional props.
export type ColumnNames = 'address' | 'matching' | 'name' | 'recomp';

export interface ReccmpSerializedReport {
  data: ReccmpComparedEntity[];
  file: string;
  format: string;
  timestamp: number;
}

export interface ReccmpInternalState {
  results: ReccmpComparedEntity[];

  // Results split into subarrays according to the pageSize.
  pages: ReccmpComparedEntity[][];

  // Sort column and direction
  sortCol: ColumnNames;
  sortDesc: boolean;

  // Query text and which fields to search.
  query: string;
  filterType: number;

  // Row filtering
  hidePerfect: boolean;
  hideStub: boolean;

  // Column hiding
  showRecomp: boolean;

  // Rows with detail row (keyed by address)
  expanded: Record<string, boolean>;

  // Paging. Numbers are 0-based. Display components add 1 to both for.
  currentPage: ReccmpComparedEntity[];
  pageNumber: number;
  maxPageNumber: number;
  pageSize: number;
}

export type InternalStateCallback = (state: ReccmpInternalState) => void;
