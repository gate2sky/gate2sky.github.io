// Renders pages/og.png, the 1200×630 picture link previews show (Slack,
// WhatsApp, iMessage, Telegram, X…): the landing's hero in its dark theme,
// without the menu, the install command and the links under it.
//
//     node scripts/landing/og.js
//
// Run it after changing the hero, once pages/index.html is generated.
const path = require("path")
const { pathToFileURL } = require("url")
const { chromium } = require("playwright")

const pages = path.join(__dirname, "../../pages")

;(async () => {
  const browser = await chromium.launch()
  const page = await browser.newPage({ viewport: { width: 1200, height: 630 }, colorScheme: "dark" })
  await page.goto(pathToFileURL(path.join(pages, "index.html")).href)
  await page.addStyleTag({ content: `
    nav, .install, .cta { display: none !important; }
    .hero { min-height: 520px; align-items: center; }
    .hero-text .lede { font-size: 22px; max-width: 30ch; }
    *, *::before, *::after { animation-play-state: paused !important; }
  ` })
  await page.locator(".hero-text .lede").evaluate(p => {
    p.textContent = "Encrypted SSH tunnels from your machine to your own domain, managed from a web dashboard."
  })
  await page.evaluate(() => document.fonts.ready)
  await page.screenshot({ path: path.join(pages, "og.png") })
  await browser.close()
})()
