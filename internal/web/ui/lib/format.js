// How times and sizes read on the page.

// Go's zero time, for "never".
const isSet = time => Boolean(time) && !String(time).startsWith("0001-")

export const ago = time => {
  if (!isSet(time)) return "never"
  const seconds = (Date.now() - new Date(time).getTime()) / 1000
  if (seconds < 60) return "just now"
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 48 * 3600) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

export const date = time =>
  isSet(time) ? new Date(time).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "—"

export const dateTime = time => (isSet(time) ? new Date(time).toLocaleString() : "never")

export const bytes = n => {
  if (n < 1024) return `${n} B`
  const units = "KMGTPE"
  let value = n / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return `${value.toFixed(1)} ${units[unit]}iB`
}

export const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`
