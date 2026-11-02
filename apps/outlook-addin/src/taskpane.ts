import { bannerModel, fetchVerdict, renderBanner, sendFeedback } from "@ap/ui";
import { clearToken, connectionFromStorage, restIdFor, saveToken } from "./helpers.ts";

// Office.js is loaded from Microsoft's CDN by taskpane.html and only exists inside Outlook.
declare const Office: any;

const root = document.getElementById("root")!;
const conn = () => connectionFromStorage(localStorage, location.origin);
const ID_FORMAT = { idFormat: "outlook_rest" } as const;

function text(tag: "p" | "div", content: string, style = ""): HTMLElement {
  const el = document.createElement(tag);
  el.textContent = content;
  if (style) el.style.cssText = style;
  return el;
}
const show = (...nodes: HTMLElement[]) => root.replaceChildren(...nodes);

function signInForm(): HTMLElement {
  const form = document.createElement("form");
  form.append(text("p", "Paste the session token your administrator gave you to connect this add-in to your server."));
  const input = document.createElement("input");
  input.type = "password";
  input.autocomplete = "off";
  input.placeholder = "Session token";
  input.style.cssText = "width:100%;box-sizing:border-box;padding:6px";
  const btn = document.createElement("button");
  btn.type = "submit";
  btn.textContent = "Connect";
  btn.style.cssText = "margin-top:8px;padding:6px 12px";
  form.append(input, btn);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    if (input.value.trim()) { saveToken(localStorage, input.value); void refresh(); }
  });
  return form;
}

function signOutLink(): HTMLElement {
  const a = document.createElement("a");
  a.href = "#";
  a.textContent = "Disconnect";
  a.style.cssText = "font-size:12px;display:inline-block;margin-top:12px";
  a.addEventListener("click", (e) => { e.preventDefault(); clearToken(localStorage); void refresh(); });
  return a;
}

async function refresh(): Promise<void> {
  const c = conn();
  if (!c.token) return show(signInForm());
  const item = Office.context.mailbox.item;
  const restId = restIdFor(item?.itemId, (id, v) => Office.context.mailbox.convertToRestId(id, Office.MailboxEnums.RestVersion[v === "v1.0" ? "v1_0" : "v2_0"]));
  if (!restId) return show(text("p", "Open a received message to see its safety check."), signOutLink());

  show(text("p", "Checking this message..."));
  const dto = await fetchVerdict(restId, c, fetch, ID_FORMAT);
  if (!dto) return show(text("p", "No result yet. If this keeps happening, your session may have expired."), signOutLink());
  const model = bannerModel(dto);
  if (!model) return show(text("p", "No signs of phishing found in this message.", "color:#1a7f37;font-weight:600"), signOutLink());
  show(renderBanner(model, document, { onFeedback: (label) => sendFeedback(restId, c, label, fetch, ID_FORMAT) }), signOutLink());
}

Office.onReady(() => {
  void refresh();
  // The pane can stay open while the user clicks through messages.
  Office.context.mailbox.addHandlerAsync?.(Office.EventType.ItemChanged, () => void refresh());
});
