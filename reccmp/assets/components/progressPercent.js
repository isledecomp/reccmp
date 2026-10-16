import { global_reccmp_progress } from '../globals';

// reccmp-pack-begin
class ProgressPercent extends window.HTMLElement {
  connectedCallback() {
    this.textContent = global_reccmp_progress.progress.toFixed(2);
  }
}

// reccmp-pack-end
export default ProgressPercent;
