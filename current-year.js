if (!customElements.get('current-year')) {
  customElements.define('current-year', class extends HTMLElement {
    connectedCallback() {
      this.textContent = String(new Date().getFullYear());
    }
  });
}
