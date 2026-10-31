import { global_reccmp_metadata } from '../globals';

// reccmp-pack-begin
class ReportFilename extends window.HTMLElement {
  connectedCallback() {
    this.textContent = global_reccmp_metadata.file;
  }
}

// reccmp-pack-end
export default ReportFilename;
