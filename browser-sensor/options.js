import {applyBlocking, cleanSites} from "./blocking.js";

const $ = (id) => document.getElementById(id);
chrome.storage.local.get(["pairToken", "blocking"], ({pairToken, blocking}) => {
  const b = blocking || {};
  $("token").value = pairToken || "";
  $("replay").checked = b.replay === true;
  $("pixels").checked = b.pixels === true;
  $("allow").value = (b.allow || []).join("\n");
});
$("save").onclick = async () => {
  const blocking = {replay: $("replay").checked, pixels: $("pixels").checked,
                    allow: cleanSites($("allow").value)};
  $("allow").value = blocking.allow.join("\n");
  await chrome.storage.local.set({pairToken: $("token").value.trim(), blocking});
  try {
    const {enabled} = await applyBlocking(chrome, blocking);
    $("status").textContent = enabled.length ? "Saved. Blocking: " + enabled.join(", ") + "." : "Saved. Nothing is blocked.";
  } catch (e) {
    $("status").textContent = "Saved, but the browser refused the change: " + e.message;
  }
};
