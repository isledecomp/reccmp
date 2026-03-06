// reccmp-pack-begin
function copyToClipboard(value) {
  navigator.clipboard.writeText(value);
}

class ClickToCopy extends window.HTMLElement {
  connectedCallback() {
    this.addEventListener('mouseout', () => {
      this.removeAttribute('copied');
    });

    this.addEventListener('click', (evt) => {
      copyToClipboard(evt.target.textContent);
      this.setAttribute('copied', '');
      // Display "copied!" message for up to 2 seconds
      // if the user keeps their mouse on the link.
      setTimeout(() => {
        this.removeAttribute('copied');
      }, 2000);
    });
  }
}

// reccmp-pack-end
export default ClickToCopy;
