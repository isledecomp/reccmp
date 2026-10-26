/** @import {ReccmpSerializedReport, ReccmpComparedEntity, ReccmpProgressCounters} from './types' */

// reccmp-pack-begin

/** @type {ReccmpSerializedReport[]} */
const [{ data: global_reccmp_data, ...global_reccmp_metadata }] = [
  /* RECCMP_REPORT_JSON */
];

// Unwrap array of functions into a dictionary with address as the key.
const dataDict = Object.fromEntries(
  global_reccmp_data.map(
    /**
     * @param {ReccmpComparedEntity} row
     * @returns {[string, ReccmpComparedEntity]}
     */
    (row) => [row.address, row],
  ),
);

/**
 * @param {string} addr
 * @returns {ReccmpComparedEntity}
 */
function getDataByAddr(addr) {
  return dataDict[addr];
}

/**
 * Entities without a type (from older reports) are considered functions.
 * @param {ReccmpComparedEntity} row
 * @returns {boolean}
 */
function isFunction(row) {
  return row.type === undefined || row.type === 1;
}

/**
 * @param {number} value
 * @returns {number}
 */
function safeDenominator(value) {
  return value === 0 ? 1 : value;
}

/**
 * Same counters as the summary printed by reccmp-asmcmp.
 * @returns {ReccmpProgressCounters}
 */
function getProgressCounters() {
  const functions = global_reccmp_data.filter(isFunction);
  const functionCount = Math.max(global_reccmp_metadata.function_count ?? 0, functions.length);

  let implementedCount = 0;
  let totalEffectiveAccuracy = 0;

  for (const row of functions) {
    if (!row.stub) {
      implementedCount += 1;
      totalEffectiveAccuracy += row.effective ? 1.0 : row.matching;
    }
  }

  return {
    implementedCount,
    functionCount,
    implemented: (implementedCount / safeDenominator(functionCount)) * 100,
    accuracy: (totalEffectiveAccuracy / safeDenominator(implementedCount)) * 100,
    progress: (totalEffectiveAccuracy / safeDenominator(functionCount)) * 100,
  };
}

const global_reccmp_progress = getProgressCounters();

// reccmp-pack-end

export { getDataByAddr, global_reccmp_data, global_reccmp_metadata, global_reccmp_progress };
