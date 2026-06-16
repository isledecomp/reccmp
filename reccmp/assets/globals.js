/** @import {ReccmpSerializedReport, ReccmpComparedEntity} from './types' */

/**
 * @typedef {object} ReccmpWindowProps
 * @property {ReccmpSerializedReport} global_reccmp_report
 */

// reccmp-pack-begin

/** @type {Window & ReccmpWindowProps} */
const reccmpWindow = /** @type {?} */ (window);

const { data: global_reccmp_data, ...global_reccmp_metadata } = reccmpWindow.global_reccmp_report;

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

// reccmp-pack-end

export { global_reccmp_data, global_reccmp_metadata, getDataByAddr };
