const printButton = document.getElementById("print-cv");
if (printButton) printButton.addEventListener("click", () => window.print());

// PaperMod scrolls fragment links without moving keyboard focus.
const skipLink = document.querySelector(".skip-link");
if (skipLink) {
  skipLink.addEventListener("click", () => {
    document.getElementById("main").focus({ preventScroll: true });
  });
}
