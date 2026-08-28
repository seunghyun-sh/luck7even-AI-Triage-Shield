const menuButton = document.querySelector("[data-menu-button]");
const menu = document.querySelector("[data-menu]");

if (menuButton && menu) {
  menuButton.addEventListener("click", () => menu.classList.toggle("is-open"));
}

const year = document.querySelector("[data-current-year]");
if (year) year.textContent = new Date().getFullYear();

const stockStatus = document.querySelector("[data-stock-status]");
if (stockStatus) {
  const productId = stockStatus.dataset.productId;
  fetch(`/products/stock?product_id=${encodeURIComponent(productId)}`)
    .then((response) => response.json())
    .then((result) => {
      stockStatus.textContent = result.available ? "구매 가능" : "품절 또는 판매 중지";
    })
    .catch(() => {
      stockStatus.textContent = "재고 정보를 확인할 수 없습니다";
    });
}

const previewRoot = document.querySelector("[data-support-preview]");
if (previewRoot) {
  const form = previewRoot.querySelector("[data-preview-form]");
  const input = previewRoot.querySelector("[data-preview-input]");
  const output = previewRoot.querySelector("[data-preview-output]");
  const securityMode = previewRoot.dataset.securityMode;

  const renderPreview = () => {
    const params = new URLSearchParams(window.location.hash.slice(1));
    const message = params.get("message") || "왼쪽에서 내용을 입력해 주세요.";
    input.value = params.get("message") || "";
    if (securityMode === "vulnerable") {
      // Intentionally unsafe DOM sink for the isolated XSS training mode.
      output.innerHTML = message;
    } else {
      output.textContent = message;
    }
  };

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    window.location.hash = new URLSearchParams({ message: input.value }).toString();
    renderPreview();
  });
  window.addEventListener("hashchange", renderPreview);
  renderPreview();
}
