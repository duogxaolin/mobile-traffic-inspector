# UI DNA

## Design tokens

- Dark operational surfaces dominate, with a cooler blue-black base and subtle radial depth.
- Accent color carries primary action and live/secure state; purple is reserved as a secondary gradient partner.
- Cards use soft borders, medium radius, and restrained shadows to separate dense operational panels.
- Typography is compact, system-based, and slightly letter-spaced for labels and status chips.

## Component patterns

- Primary actions use gradient fill, small icon support, and compact padding.
- Secondary actions use bordered dark fills and hover brightening.
- Setup flows are shown as cards with numbered steps, muted helper copy, and one safety callout.
- Lists favor dense rows with a small icon/avatar, primary label, muted metadata, and a right-side action.

## Interaction and motion

- Loading states use small rotating icons or pulsing dots instead of large blocking spinners.
- Destructive actions require explicit confirmation and use danger coloring only on the action itself.
- Sensitive operations use inline errors and audited action language instead of modal-heavy interruption.

## Accessibility baseline

- Interactive icons need text labels or `aria-label` when text is absent.
- Focusable controls should remain keyboard-reachable and preserve visible button roles.
- Copy must explain security-sensitive outputs before revealing or downloading them.

## Voice and tone

- Copy is operational, concise, and explicit about risk.
- Empty/error states should explain what to do next, not just what went wrong.

## Layout and responsive

- Desktop uses two-column cards/panels when comparing setup versus current state.
- Mobile collapses cards to one column and keeps action targets compact but readable.

## Anti-patterns

- Do not expose raw secrets without naming the risk.
- Do not add decorative UI that competes with request/device state.
- Do not hide required setup commands or trust steps behind vague “advanced” wording.
