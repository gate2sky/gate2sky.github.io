// Where the theme is served from, on whatever page shows the demo — the
// dashboard's /ui/theme/default/, or GitHub Pages' /intergate/theme/: the
// folder above this one. See RECORD/2026-10-29.a-design-system.completed.md.

export const THEME = new URL("../", import.meta.url).pathname
