# UI DNA

## Design tokens

- Light operational surfaces dominate: white working panels sit on a very light slate canvas.
- Emerald is the single primary accent for actions, active navigation, live state, security, and focus rings.
- Semantic amber and rose are reserved for warnings and destructive/error states; they never compete with primary actions.
- Cards use slate borders, 16–24px radius, and restrained shadows to separate dense operational content.
- Typography is system-based, compact in data views, and stronger in page hierarchy.

## Component patterns

- Primary actions use a solid emerald fill, small icon support, and a clear visible focus ring.
- Secondary actions use white surfaces, slate borders, and an emerald-tinted hover state.
- Setup flows are shown as cards with numbered steps, muted helper copy, and one safety callout.
- Lists favor dense rows with a small icon/avatar, primary label, muted metadata, and a right-side action.
- Operational code and payload previews may use a dark inset surface for readability inside the light interface.

## Interaction and motion

- Loading states use small rotating icons or pulsing dots instead of large blocking spinners.
- Destructive actions require explicit confirmation and use danger coloring only on the action itself.
- Sensitive operations use inline errors and audited action language instead of modal-heavy interruption.
- Navigation and filters reveal progressively on small screens to protect the primary data view.

## Accessibility baseline

- Interactive icons need text labels or `aria-label` when text is absent.
- Focusable controls remain keyboard-reachable and use a visible emerald focus ring.
- Copy must explain security-sensitive outputs before revealing or downloading them.
- Status is conveyed with text as well as color.
- Closed off-canvas navigation leaves the accessibility tree and tab order; Escape closes it when open.

## Voice and tone

- Vietnamese is the primary interface language; technical protocol terms remain unchanged where translation would reduce clarity.
- Copy is operational, concise, and explicit about risk.
- Empty/error states should explain what to do next, not just what went wrong.

## Layout and responsive

- Desktop uses two-column cards/panels when comparing setup versus current state.
- Mobile collapses cards to one column and keeps action targets compact but readable.
- Dense tables keep horizontal scroll rather than hiding required operational data.

## Anti-patterns

- Do not expose raw secrets without naming the risk.
- Do not add decorative UI that competes with request/device state.
- Do not hide required setup commands or trust steps behind vague “advanced” wording.
- Do not reintroduce dark application chrome, gradients on primary actions, or multiple competing accent colors.
