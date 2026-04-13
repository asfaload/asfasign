// Add a "Back to asfaload.com" link in the menu bar.
// This script is loaded at the end of <body> by mdBook, so the DOM is
// already parsed — no DOMContentLoaded needed, just run immediately.
// Uses inline SVG matching mdBook's icon style (class="fa-svg").
(function () {
  const menuBar = document.querySelector(".right-buttons");
  if (menuBar) {
    const link = document.createElement("a");
    link.href = "https://asfaload.com";
    link.title = "Back to asfaload.com";
    link.target = "_blank";
    link.rel = "noopener";
    link.innerHTML =
      '<span class="fa-svg"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 576 512">' +
      '<path d="M575.8 255.5c0 18-15 32.1-32 32.1h-32l.7 160.2c0 2.7-.2 5.4-.5 8.1V472c0 22.1-17.9 40-40 40H456c-1.1 0-2.2 0-3.3-.1c-1.4 .1-2.8 .1-4.2 .1H416 392c-22.1 0-40-17.9-40-40V400 336c0-26.5-21.5-48-48-48H272c-26.5 0-48 21.5-48 48v64 72c0 22.1-17.9 40-40 40H160 128.1c-1.5 0-3-.1-4.5-.2c-1.2 .1-2.4 .2-3.6 .2H104c-22.1 0-40-17.9-40-40v-72c0-.7 0-1.3 0-2V280 256 245.6c0-3.7-.2-7.3-.5-10.9v-.5c0-4.5-.5-8.9-1.3-13.2H32c-18 0-32-14-32-32.1c0-9 3-17 10-24L266.4 8c7-7 15-8 22-8s15 2 21 7L564.8 231.5c8 7 12 15 11 24z"/>' +
      "</svg></span>";
    menuBar.insertBefore(link, menuBar.firstChild);
  }
})();
