// All Gmail DOM knowledge lives here, so markup changes are a one-file fix.
export const MESSAGE_SELECTOR = "[data-legacy-message-id]";
export const messageIdOf = (el: Element): string | null => el.getAttribute("data-legacy-message-id");
