"use strict";
(() => {
  const select = document.querySelector("[data-provider-setup]");
  if (!select) return;
  const form = select.form;
  function update() {
    form.querySelectorAll("[data-provider-modes]").forEach(group => {
      const active = group.dataset.providerModes.split(" ").includes(select.value);
      group.hidden = !active;
      group.querySelectorAll("input, select").forEach(input => { input.disabled = !active; });
    });
  }
  select.addEventListener("change", update);
  update();
})();
