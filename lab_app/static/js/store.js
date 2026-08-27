const menuButton = document.querySelector("[data-menu-button]");
const menu = document.querySelector("[data-menu]");

if (menuButton && menu) {
  menuButton.addEventListener("click", () => menu.classList.toggle("is-open"));
}

const year = document.querySelector("[data-current-year]");
if (year) year.textContent = new Date().getFullYear();
