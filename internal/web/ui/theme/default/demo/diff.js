// A change to a file as a unified diff, the way `git apply` takes it: the
// lines both texts share by their longest common subsequence, and hunks of
// what differs with three lines around each. Line by line, for files of a
// few hundred lines — what a component is.

const lines = text => {
  const all = text.split("\n")
  // A file's last newline ends its last line; it is not a line of its own.
  if (all[all.length - 1] === "") all.pop()
  return all
}

export const unifiedDiff = (before, after, path, context = 3) => {
  const a = lines(before)
  const b = lines(after)
  const n = a.length
  const m = b.length

  // common[i][j]: the longest common subsequence of a[i…] and b[j…].
  const common = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1))
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      common[i][j] = a[i] === b[j] ? common[i + 1][j + 1] + 1 : Math.max(common[i + 1][j], common[i][j + 1])
    }
  }

  // The edit, line by line, with where each line is in both files.
  const ops = []
  let i = 0
  let j = 0
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) ops.push([" ", a[i], i++, j++])
    else if (j >= m || (i < n && common[i + 1][j] >= common[i][j + 1])) ops.push(["-", a[i], i++, j])
    else ops.push(["+", b[j], i, j++])
  }

  // Hunks: each change with its context, merged where their contexts meet.
  const ranges = []
  ops.forEach(([kind], at) => {
    if (kind === " ") return
    const start = Math.max(0, at - context)
    const end = Math.min(ops.length, at + context + 1)
    const last = ranges[ranges.length - 1]
    if (last && start <= last[1]) last[1] = end
    else ranges.push([start, end])
  })
  if (!ranges.length) return ""

  let out = `diff --git a/${path} b/${path}\n--- a/${path}\n+++ b/${path}\n`
  for (const [start, end] of ranges) {
    const hunk = ops.slice(start, end)
    const from = hunk.filter(([kind]) => kind !== "+").length
    const to = hunk.filter(([kind]) => kind !== "-").length
    const [, , ai, bi] = hunk[0]
    out += `@@ -${from ? ai + 1 : ai},${from} +${to ? bi + 1 : bi},${to} @@\n`
    for (const [kind, line] of hunk) out += kind + line + "\n"
  }
  return out
}
