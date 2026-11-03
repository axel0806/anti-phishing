## What and why

<!-- One or two sentences. Link the issue if there is one: "Fixes #123". -->

## How I tested it

- [ ] I wrote a test that fails without this change
- [ ] `npm test` and `npm run typecheck` pass
- [ ] For detection changes: `npm run corpus` still shows 0 false positives, and I added a test that a legitimate look-alike does not fire

## Checklist

- [ ] The AI can still only add points; nothing new stores message bodies or sends URL paths or tokens outside the process
- [ ] Any new regular expression over email or attachment content uses bounded repetition
- [ ] Docs are updated if behaviour or configuration changed
