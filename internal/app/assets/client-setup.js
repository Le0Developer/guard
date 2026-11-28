"use strict";
(() => {
  const select = document.querySelector("[data-client-setup]");
  if (!select) return;
  function update() {
    select.form.querySelectorAll("[data-client-types]").forEach(group => {
      const active = group.dataset.clientTypes.split(" ").includes(select.value);
      group.hidden = !active;
      group.disabled = !active;
    });
  }
  select.addEventListener("change", update);
  update();
})();
