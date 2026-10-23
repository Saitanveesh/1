"use strict";
// Fake-data-only training client. The intentionally vulnerable behavior is on
// the isolated PC-5 server, never in this UI. Render all response text safely.
const $ = (id) => document.getElementById(id);
function show(id, value, failed = false) {
  const node = $(id);
  node.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  node.classList.toggle("failure", failed);
}
async function request(path, options) {
  const result = await fetch(path, { cache: "no-store", ...options });
  const text = await result.text();
  let body;
  try { body = JSON.parse(text); } catch { body = text; }
  return { status: result.status, body };
}
$("notice-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const value = $("notice-query").value;
  show("notice-result", "Requesting fictional notice fixture…");
  try {
    const result = await request("/api/notices?q=" + encodeURIComponent(value));
    show("notice-result", result);
  } catch (error) {
    show("notice-result", String(error), true);
  }
});
$("student-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  show("student-result", "Requesting fictional student fixture…");
  try {
    const id = encodeURIComponent($("student-id").value);
    const viewer = encodeURIComponent($("viewer-id").value);
    show("student-result", await request("/api/student?id=" + id + "&viewer=" + viewer));
  } catch (error) { show("student-result", String(error), true); }
});
$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  show("login-result", "Testing fictional account…");
  try {
    const result = await request("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: $("login-name").value,
        password: $("login-password").value,
      }),
    });
    show("login-result", result, result.status !== 200);
  } catch (error) { show("login-result", String(error), true); }
});
$("traversal-normal").addEventListener("click", async () => {
  const result = await fetch("/download?file=public-notice.txt", { cache: "no-store" });
  show("download-result", { status: result.status, text: await result.text() });
});
$("traversal-test").addEventListener("click", async () => {
  // This is a known fixture under the isolated training directory.
  const result = await fetch("/download?file=../training-private/lab-only.txt", { cache: "no-store" });
  show("download-result", { status: result.status, text: await result.text() });
});
