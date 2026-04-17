// reccmp-pack-begin
const { data: global_reccmp_data, ...global_reccmp_metadata } = window.global_reccmp_report;

// Unwrap array of functions into a dictionary with address as the key.
const dataDict = Object.fromEntries(global_reccmp_data.map((row) => [row.address, row]));

function getDataByAddr(addr) {
  return dataDict[addr];
}

// reccmp-pack-end

export { global_reccmp_data, global_reccmp_metadata, getDataByAddr };
