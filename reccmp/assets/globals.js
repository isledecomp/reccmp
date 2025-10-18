// reccmp-pack-begin
const global_reccmp_data = window.global_reccmp_report.data;

// Unwrap array of functions into a dictionary with address as the key.
const dataDict = Object.fromEntries(global_reccmp_data.map((row) => [row.address, row]));

function getDataByAddr(addr) {
  return dataDict[addr];
}

// reccmp-pack-end

export { global_reccmp_data, getDataByAddr };
