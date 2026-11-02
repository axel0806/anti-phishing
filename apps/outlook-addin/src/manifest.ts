/** Stable id of this add-in. Changing it makes Outlook treat the add-in as a different product. */
export const ADDIN_ID = "7c3b8d2e-4f1a-4a8e-9b53-2a6f0c1d9e41";

const xmlEscape = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");

/** Only a plain https origin (or http on localhost, for development) may be baked into the manifest. */
function normaliseOrigin(input: string): string {
  const u = new URL(input); // throws for garbage
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) throw new Error("The add-in origin must be https (http is allowed for localhost only)");
  return u.origin;
}

/**
 * Office add-in manifest (read mode, task pane). Permissions are ReadItem only: the add-in shows a verdict and sends
 * feedback to our server, it never needs to read or change the mailbox itself.
 */
export function renderManifest(originInput: string, opts: { displayName?: string; version?: string } = {}): string {
  const origin = normaliseOrigin(originInput);
  const name = xmlEscape(opts.displayName ?? "Anti-Phishing");
  const base = `${origin}/addin`;
  return `<?xml version="1.0" encoding="UTF-8"?>
<OfficeApp xmlns="http://schemas.microsoft.com/office/appforoffice/1.1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="MailApp">
  <Id>${ADDIN_ID}</Id>
  <Version>${xmlEscape(opts.version ?? "1.0.0.0")}</Version>
  <ProviderName>Anti-Phishing</ProviderName>
  <DefaultLocale>en-US</DefaultLocale>
  <DisplayName DefaultValue="${name}"/>
  <Description DefaultValue="Shows whether the open email looks like phishing, and why."/>
  <IconUrl DefaultValue="${base}/icon-64.png"/>
  <HighResolutionIconUrl DefaultValue="${base}/icon-128.png"/>
  <SupportUrl DefaultValue="${origin}/admin/"/>
  <AppDomains>
    <AppDomain>${origin}</AppDomain>
  </AppDomains>
  <Hosts>
    <Host Name="Mailbox"/>
  </Hosts>
  <Requirements>
    <Sets>
      <Set Name="Mailbox" MinVersion="1.5"/>
    </Sets>
  </Requirements>
  <FormSettings>
    <Form xsi:type="ItemRead">
      <DesktopSettings>
        <SourceLocation DefaultValue="${base}/taskpane.html"/>
        <RequestedHeight>260</RequestedHeight>
      </DesktopSettings>
    </Form>
  </FormSettings>
  <Permissions>ReadItem</Permissions>
  <Rule xsi:type="RuleCollection" Mode="Or">
    <Rule xsi:type="ItemIs" ItemType="Message" FormType="Read"/>
  </Rule>
  <DisableEntityHighlighting>false</DisableEntityHighlighting>
</OfficeApp>
`;
}
