// Writes internal/web/ui/logo-mark.svg, the logo without its comments, for
// the dashboard's header and sign-in page (as the landing's header inlines
// it), and renders pages/favicon.svg into the bitmaps for what does not take
// an SVG icon: favicon.ico (16 and 32 px; older Safari, and the /favicon.ico every
// browser asks for) and apple-touch-icon.png (180 px, on a dark tile edge to
// edge, without rounded corners: iOS rounds them itself and fills
// transparency with black).
//
//     node scripts/landing/icons.js
const fs = require("fs")
const path = require("path")
const { chromium } = require("playwright")

const pages = path.join(__dirname, "../../pages")
const source = fs.readFileSync(path.join(pages, "favicon.svg"), "utf8")
const dataURL = svg => "data:image/svg+xml;base64," + Buffer.from(svg).toString("base64")
const svg = dataURL(source)
// The favicon has no tile: only the apple-touch-icon is drawn on one.
const tile = dataURL(source.replace("</defs>", `  <radialGradient id="tile" cx=".6" cy=".3" r=".8"><stop offset="0" stop-color="#0a1a3d"/><stop offset="1" stop-color="#040815"/></radialGradient>
  </defs>
  <rect width="64" height="64" fill="url(#tile)"/>`))

// The desktop app's tray icon is the favicon too.
process.on("exit", () => fs.copyFileSync(path.join(pages, "favicon.ico"), path.join(__dirname, "../../cmd/intergate-gui/icon.ico")))

// The same cut as hero.brand() in gen.py's hero.py: no comments.
fs.writeFileSync(path.join(__dirname, "../../internal/web/ui/logo-mark.svg"), source
  .replace(/<!--[\s\S]*?-->\s*/g, ""))
// The desktop app's window shows it too.
fs.copyFileSync(path.join(__dirname, "../../internal/web/ui/logo-mark.svg"), path.join(__dirname, "../../internal/clientapp/ui/logo.svg"))

async function render(browser, size, { src = svg, background = "transparent", inset = 0 } = {}) {
  const page = await browser.newPage({ viewport: { width: size, height: size } })
  const icon = size - 2 * inset
  await page.setContent(`<body style="margin:0;background:${background}">
    <img src="${src}" width="${icon}" height="${icon}" style="display:block;margin:${inset}px">`)
  await page.locator("img").evaluate(img => img.decode())
  const png = await page.screenshot({ omitBackground: background === "transparent" })
  await page.close()
  return png
}

// An ICO that holds PNGs: a header, one 16-byte entry per image, the images.
function ico(images) {
  const head = Buffer.alloc(6 + 16 * images.length)
  head.writeUInt16LE(1, 2)
  head.writeUInt16LE(images.length, 4)
  let offset = head.length
  images.forEach(({ size, png }, i) => {
    const at = 6 + 16 * i
    head.writeUInt8(size, at)
    head.writeUInt8(size, at + 1)
    head.writeUInt16LE(1, at + 4)
    head.writeUInt16LE(32, at + 6)
    head.writeUInt32LE(png.length, at + 8)
    head.writeUInt32LE(offset, at + 12)
    offset += png.length
  })
  return Buffer.concat([head, ...images.map(image => image.png)])
}

;(async () => {
  const browser = await chromium.launch()
  const images = []
  for (const size of [16, 32]) images.push({ size, png: await render(browser, size) })
  fs.writeFileSync(path.join(pages, "favicon.ico"), ico(images))
  fs.writeFileSync(path.join(pages, "apple-touch-icon.png"), await render(browser, 180, { src: tile }))
  await browser.close()
})()
