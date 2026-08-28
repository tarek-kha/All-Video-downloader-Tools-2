import path from "path"
import { promises as fs } from "fs"
import {
  execFileAsync,
  cookieArgs,
  MAX_FILESIZE,
  poTokenArgs,
  youtubeArgs,
  platformKey,
} from "./ytdlp"
import { validateMediaFile } from "./validate"
import {
  safeFetch,
  readLimited,
  UnsafeUrlError,
} from "./security/safe-fetch"

export const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

// ---------------------------------------------------------------------------
// Failure classification
// ---------------------------------------------------------------------------

export type FailureCategory =
  | "INVALID_URL"
  | "BLOCKED_URL"
  | "UNSUPPORTED_URL"
  | "VIDEO_UNAVAILABLE"
  | "PRIVATE_CONTENT"
  | "LOGIN_REQUIRED"
  | "PO_TOKEN_REQUIRED"
  | "AGE_RESTRICTED"
  | "GEO_RESTRICTED"
  | "DRM"
  | "ANTI_BOT"
  | "RATE_LIMITED"
  | "NO_FORMAT"
  | "FILE_TOO_LARGE"
  | "RESOLVE_TIMEOUT"
  | "DOWNLOAD_TIMEOUT"
  | "UPSTREAM_ERROR"
  | "VALIDATION_FAILED"
  | "SERVER_BUSY"
  | "INTERNAL_ERROR"

export interface ExtractionFailure {
  category: FailureCategory
  message: string
  detail: string
}

const CATEGORY_MESSAGES: Record<FailureCategory, string> = {
  INVALID_URL: "The provided URL is invalid.",
  BLOCKED_URL:
    "This URL points to a private/internal address and cannot be fetched.",
  UNSUPPORTED_URL: "This URL is not supported by the extractor.",
  VIDEO_UNAVAILABLE:
    "This video appears to be unavailable, deleted, or no longer accessible.",
  PRIVATE_CONTENT:
    "This video is private and cannot be downloaded without access.",
  LOGIN_REQUIRED:
    "This video requires login. Add valid cookies for this platform and try again.",
  PO_TOKEN_REQUIRED:
    "This platform requires a server-side proof-of-origin (PO) token — this is not a login problem and cookies will not help. The PO-token provider must be configured on the server.",
  AGE_RESTRICTED:
    "This content is age-restricted and requires an authenticated account.",
  GEO_RESTRICTED:
    "This video is geo-restricted by its uploader/platform and isn't available from the server's region — this is unrelated to cookies or login.",
  DRM:
    "This video is DRM-protected (encrypted). Downloading it is not technically possible.",
  ANTI_BOT:
    "The site is blocking automated access (anti-bot / CAPTCHA / datacenter IP block). Cookies are unlikely to fix this.",
  RATE_LIMITED:
    "The upstream platform rate-limited this request. Please wait and try again.",
  NO_FORMAT:
    "The selected format/quality is not available for this video.",
  FILE_TOO_LARGE:
    `This file is larger than the ${MAX_FILESIZE} limit — try a lower quality.`,
  RESOLVE_TIMEOUT:
    "Resolving video metadata timed out. Please retry.",
  DOWNLOAD_TIMEOUT:
    "Downloading the media timed out. Try a lower quality and retry.",
  UPSTREAM_ERROR:
    "The upstream platform returned an unexpected server error.",
  VALIDATION_FAILED:
    "Downloaded output failed media validation.",
  SERVER_BUSY:
    "The download server is busy. Please try again shortly.",
  INTERNAL_ERROR:
    "Request failed due to an internal server error.",
}

function runtimeErrorText(rawMsg: string): string {
  const errorMarker = rawMsg.search(/\bERROR:\s/i)
  const base = errorMarker >= 0 ? rawMsg.slice(errorMarker) : rawMsg

  return base
    .replace(/(?:^|\n)\s*(?:Error:\s*)?Command failed:[^\n]*/g, "")
    .replace(/\s+/g, " ")
    .trim()
}

function compactDetail(raw: string): string {
  return runtimeErrorText(raw).slice(0, 240)
}

export function classifyFailure(
  rawMsg: string,
  phase: "resolve" | "download" = "download"
): ExtractionFailure {
  const m = runtimeErrorText(rawMsg).toLowerCase()

  let category: FailureCategory = "INTERNAL_ERROR"

  if (/invalid url|only http\(s\)|malformed url/.test(m)) {
    category = "INVALID_URL"
  } else if (/blocked unsafe url|private\/internal/.test(m)) {
    category = "BLOCKED_URL"
  } else if (/server is busy|maximum number of downloads/.test(m)) {
    category = "SERVER_BUSY"
  } else if (/drm|widevine|fairplay|playready|encrypted media|license url/.test(m)) {
    category = "DRM"
  } else if (
    /not available in your (country|region)|geo.?restrict|geoblock|geo.?block/.test(
      m
    )
  ) {
    category = "GEO_RESTRICTED"
  } else if (/confirm your age|age.?restrict|age.?verification/.test(m)) {
    category = "AGE_RESTRICTED"
  } else if (/private video|private content/.test(m)) {
    category = "PRIVATE_CONTENT"
  } else if (/\bpo.?token\b/.test(m)) {
    category = "PO_TOKEN_REQUIRED"
  } else if (
    /sign in|log ?in required|login required|authentication required/.test(m)
  ) {
    category = "LOGIN_REQUIRED"
  } else if (/cookies-from-browser/.test(m)) {
    category = "ANTI_BOT"
  } else if (/too many requests|rate.?limit|429/.test(m)) {
    category = "RATE_LIMITED"
  } else if (
    /captcha|cloudflare|access denied|forbidden|challenge|bot|datacenter/.test(m)
  ) {
    category = "ANTI_BOT"
  } else if (
    /requested format is not available|no video formats|no suitable format/.test(
      m
    )
  ) {
    category = "NO_FORMAT"
  } else if (/file is larger than max-filesize/.test(m)) {
    category = "FILE_TOO_LARGE"
  } else if (/unsupported url/.test(m)) {
    category = "UNSUPPORTED_URL"
  } else if (
    /rejected fake media|ffprobe could not parse|not media:|no audio or video streams/.test(
      m
    )
  ) {
    category = "VALIDATION_FAILED"
  } else if (
    /video unavailable|deleted|removed|no longer available|does not exist|404|not found/.test(
      m
    )
  ) {
    category = "VIDEO_UNAVAILABLE"
  } else if (
    /http error 5\d\d|upstream 5\d\d|service unavailable|bad gateway/.test(m)
  ) {
    category = "UPSTREAM_ERROR"
  } else if (/timed out|etimedout|timeout/.test(m)) {
    category =
      phase === "resolve" ? "RESOLVE_TIMEOUT" : "DOWNLOAD_TIMEOUT"
  }

  return {
    category,
    message: CATEGORY_MESSAGES[category],
    detail: compactDetail(rawMsg),
  }
}

// ---------------------------------------------------------------------------
// Impersonation support (curl_cffi) — detected once per process
// ---------------------------------------------------------------------------

let impersonateAvailable: boolean | null = null

async function canImpersonate(): Promise<boolean> {
  if (impersonateAvailable !== null) {
    return impersonateAvailable
  }

  try {
    const { stdout } = await execFileAsync(
      "yt-dlp",
      ["--list-impersonate-targets"],
      {
        timeout: 20_000,
      }
    )

    impersonateAvailable =
      /chrome/i.test(stdout) && !/chrome.*unavailable/i.test(stdout)
  } catch {
    impersonateAvailable = false
  }

  return impersonateAvailable
}

// ---------------------------------------------------------------------------
// Page scanning: direct MP4/WebM, HLS, DASH, <video>/<source>, og:video,
// JSON-LD contentUrl, and embedded iframes (one level deep)
// ---------------------------------------------------------------------------

export interface MediaCandidate {
  url: string
  referer: string
  kind: "direct" | "hls" | "dash" | "embed"
}

const EMBED_HOST_RE =
  /(?:youtube\.com\/(?:embed|watch|shorts)|youtu\.be\/|player\.vimeo\.com\/video|vimeo\.com\/\d|dailymotion\.com\/(?:embed\/)?video|player\.twitch\.tv|streamable\.com|wistia\.(?:com|net)|brightcove\.net|jwplatform\.com|kaltura\.com|facebook\.com\/plugins\/video|rumble\.com\/embed|bitchute\.com\/embed|odysee\.com\/\$\/embed)/i

function detectEmbeds(
  html: string,
  baseUrl: string
): MediaCandidate[] {
  const out: MediaCandidate[] = []

  const push = (raw: string) => {
    try {
      const abs = new URL(raw, baseUrl).toString()

      if (EMBED_HOST_RE.test(abs)) {
        out.push({
          url: abs,
          referer: baseUrl,
          kind: "embed",
        })
      }
    } catch {
      // ignore
    }
  }

  for (const m of html.matchAll(
    /<iframe[^>]+src=["']([^"']+)["']/gi
  )) {
    push(m[1])
  }

  for (const m of html.matchAll(
    /["'](?:embedUrl|embed_url|player_url)["']\s*:\s*["']([^"']+)["']/gi
  )) {
    push(m[1])
  }

  for (const m of html.matchAll(
    /https?:\/\/(?:www\.)?(?:youtube\.com\/embed\/[\w-]{6,}|youtu\.be\/[\w-]{6,}|player\.vimeo\.com\/video\/\d+|dailymotion\.com\/embed\/video\/\w+)/gi
  )) {
    push(m[0])
  }

  const seen = new Set<string>()

  return out
    .filter((c) => {
      if (seen.has(c.url)) return false
      seen.add(c.url)
      return true
    })
    .slice(0, 4)
}

const MEDIA_URL_RE =
  /https?:\/\/[^"'\s\\<>]+?\.(?:mp4|webm|mov|m4v|mkv|m3u8|mpd)(?:\?[^"'\s\\<>]*)?/gi

const JUNK_RE =
  /thumb|sprite|preview|poster|logo|banner|advert|\/ads?[\/._-]|pixel|tracker|analytics|\.svg|blank|placeholder|trailer_sm|_fb\.mp4|apk_new|\/apk[\/._-]|app.?install|app.?download|promo_?video|splash/i

function kindOf(u: string): MediaCandidate["kind"] {
  if (/\.m3u8(\?|$)|\/hls[\/?]/i.test(u)) return "hls"
  if (/\.mpd(\?|$)|\/dash[\/?]/i.test(u)) return "dash"
  return "direct"
}

function unescapeHtml(s: string): string {
  return s
    .replace(/\\u002f/g, "/")
    .replace(/\\u0026/g, "&")
    .replace(/\\u003d/g, "=")
    .replace(/\\u003c/g, "<")
    .replace(/\\u003e/g, ">")
    .replace(/\\"/g, '"')
    .replace(/\\'/g, "'")
    .replace(/\\n/g, "\n")
    .replace(/\\t/g, "\t")
    .replace(/\\r/g, "\r")
    .replace(/\\\\/g, "\\")
}

async function fetchPage(
  url: string,
  referer?: string
): Promise<string> {
  try {
    const res = await safeFetch(url, {
      timeoutMs: 15_000,
      headers: {
        "User-Agent": BROWSER_UA,
        Accept: "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        ...(referer ? { Referer: referer } : {}),
      },
    })

    const ct = res.headers.get("content-type") ?? ""

    if (
      !res.ok ||
      /image|video|audio|octet-stream/.test(ct)
    ) {
      return ""
    }

    const body = await readLimited(
      res,
      2 * 1024 * 1024
    )

    return unescapeHtml(
      new TextDecoder().decode(body)
    )
  } catch {
    return ""
  }
}

async function fetchText(
  url: string,
  referer?: string
): Promise<string> {
  try {
    const res = await safeFetch(url, {
      timeoutMs: 15_000,
      headers: {
        "User-Agent": BROWSER_UA,
        Accept: "*/*",
        ...(referer ? { Referer: referer } : {}),
      },
    })

    if (!res.ok) return ""

    const ct = res.headers.get("content-type") ?? ""

    if (
      /image|video|audio|octet-stream|mpegurl|dash/.test(
        ct
      )
    ) {
      return ""
    }

    return new TextDecoder().decode(
      await readLimited(
        res,
        3 * 1024 * 1024
      )
    )
  } catch {
    return ""
  }
}

function collectFromHtml(
  html: string,
  baseUrl: string
): string[] {
  const found = new Set<string>()

  const add = (
    raw: string | undefined | null
  ) => {
    if (!raw) return

    try {
      const abs = new URL(
        raw,
        baseUrl
      ).toString()

      if (
        /^https?:/.test(abs) &&
        !JUNK_RE.test(abs)
      ) {
        found.add(abs)
      }
    } catch {
      // ignore bad urls
    }
  }

  for (const m of html.matchAll(MEDIA_URL_RE)) {
    if (!JUNK_RE.test(m[0])) {
      found.add(m[0])
    }
  }

  for (const m of html.matchAll(
    /<(?:video|source)[^>]+src=["']([^"']+)["']/gi
  )) {
    add(m[1])
  }

  for (const m of html.matchAll(
    /<meta[^>]+(?:property|name)=["'](?:og:video(?::(?:secure_)?url)?|twitter:player:stream)["'][^>]+content=["']([^"']+)["']/gi
  )) {
    add(m[1])
  }

  for (const m of html.matchAll(
    /<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["'](?:og:video(?::(?:secure_)?url)?|twitter:player:stream)["']/gi
  )) {
    add(m[1])
  }

  for (const m of html.matchAll(
    /["'](?:contentUrl|contentURL)["']\s*:\s*["']([^"']+)["']/gi
  )) {
    add(m[1])
  }

  return [...found]
}

const PLAYER_CONFIG_RE =
  /["'](?:videoUrl|video_url|videoSrc|hlsUrl|hls_url|streamUrl|stream_url|manifestUrl|fileUrl|file|src)["']\s*:\s*["'](https?:[^"']{12,})["']/gi

export async function scanPageForMedia(
  url: string
): Promise<MediaCandidate[]> {
  const html = await fetchPage(url)

  if (!html) return []

  const priority: MediaCandidate[] = []

  for (const m of html.matchAll(
    PLAYER_CONFIG_RE
  )) {
    const u = m[1]

    if (
      !JUNK_RE.test(u) &&
      !/\.(jpe?g|png|gif|webp|css|js|vtt|srt)(\?|$)/i.test(
        u
      )
    ) {
      priority.push({
        url: u,
        referer: url,
        kind: kindOf(u),
      })
    }
  }

  const embeds = detectEmbeds(
    html,
    url
  )

  const direct = collectFromHtml(
    html,
    url
  )

  const candidates: MediaCandidate[] =
    direct
      .filter((u) =>
        /^https?:\/\/.+\.(?:mp4|webm|mov|m4v|mkv|m3u8|mpd)(?:\?|$)/i.test(
          u
        )
      )
      .map((u) => ({
        url: u,
        referer: url,
        kind: kindOf(u),
      }))

  const iframes = [
    ...html.matchAll(
      /<iframe[^>]+src=["']([^"']+)["']/gi
    ),
  ]
    .map((m) => {
      try {
        return new URL(
          m[1],
          url
        ).toString()
      } catch {
        return ""
      }
    })
    .filter(
      (u) =>
        /^https?:/.test(u) &&
        !JUNK_RE.test(u) &&
        !/facebook|twitter|recaptcha|ads|consent/i.test(
          u
        )
    )
    .slice(0, 3)

  for (const frame of iframes) {
    const fhtml = await fetchPage(
      frame,
      url
    )

    if (!fhtml) continue

    for (const u of collectFromHtml(
      fhtml,
      frame
    )) {
      if (
        /\.(m3u8|mpd|mp4|webm|mov|m4v|mkv)(\?|$)/i.test(
          u
        )
      ) {
        candidates.push({
          url: u,
          referer: frame,
          kind: kindOf(u),
        })
      }
    }
  }

  const resolved: MediaCandidate[] = []

  for (const c of priority.slice(0, 4)) {
    const hasExt =
      /\.(m3u8|mpd|mp4|webm|mov|m4v|mkv)(\?|$)/i.test(
        c.url
      )

    if (hasExt) continue

    const body = unescapeHtml(
      await fetchText(
        c.url,
        c.referer
      )
    )

    if (!body) continue

    for (const m of body.matchAll(
      MEDIA_URL_RE
    )) {
      if (!JUNK_RE.test(m[0])) {
        resolved.push({
          url: m[0],
          referer: c.referer,
          kind: kindOf(m[0]),
        })
      }
    }

    for (const m of body.matchAll(
      /["'](?:videoUrl|video_url|file|src|url|hls|manifest)["']\s*:\s*["'](https?:[^"']{12,})["']/gi
    )) {
      const u = m[1]

      if (
        !JUNK_RE.test(u) &&
        /\.(m3u8|mpd|mp4|webm|mov|m4v|mkv)(\?|$)/i.test(
          u
        )
      ) {
        resolved.push({
          url: u,
          referer: c.referer,
          kind: kindOf(u),
        })
      }
    }
  }

  const seen = new Set<string>()

  const rank: Record<
    MediaCandidate["kind"],
    number
  > = {
    embed: -1,
    direct: 0,
    hls: 1,
    dash: 2,
  }

  const rest = candidates.sort(
    (a, b) =>
      rank[a.kind] - rank[b.kind]
  )

  return [
    ...embeds,
    ...resolved,
    ...priority,
    ...rest,
  ]
    .filter((c) => {
      if (seen.has(c.url)) {
        return false
      }

      seen.add(c.url)
      return true
    })
    .slice(0, 10)
}

// ---------------------------------------------------------------------------
// Probe (info) with fallbacks: native → impersonate → generic → page scan
// ---------------------------------------------------------------------------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type YtdlpEntry = Record<string, any>

async function runProbe(
  args: string[],
  timeout: number
): Promise<YtdlpEntry> {
  const MAX_PROBE_BUFFER =
    4 * 1024 * 1024

  let stdout: string

  try {
    const result =
      await execFileAsync(
        "yt-dlp",
        args,
        {
          maxBuffer: MAX_PROBE_BUFFER,
          timeout,
        }
      )

    stdout = result.stdout
  } catch (e) {
    if (
      e instanceof Error &&
      e.message.includes("maxBuffer")
    ) {
      const overflow = new Error(
        "yt-dlp output exceeded probe buffer limit"
      ) as Error & {
        failure: ExtractionFailure
      }

      overflow.failure = {
        category: "INTERNAL_ERROR",
        message:
          CATEGORY_MESSAGES[
            "INTERNAL_ERROR"
          ],
        detail:
          "yt-dlp output exceeded probe buffer limit",
      }

      throw overflow
    }

    throw e
  }

  const raw = JSON.parse(stdout)

  return raw?._type === "playlist"
    ? raw.entries?.[0]
    : raw
}

export async function probeWithFallbacks(
  url: string,
  cookiesPath: string | null
): Promise<YtdlpEntry> {
  const isYouTube =
    platformKey(url) === "youtube"

  const ytArgs = isYouTube
    ? [
        ...youtubeArgs(),
        ...poTokenArgs(),
      ]
    : []

  const base = [
    "-J",
    "--no-playlist",
    "--no-warnings",
    "--user-agent",
    BROWSER_UA,
    ...ytArgs,
  ]

  const noCookieBase = [...base]

  const withCookieBase = [
    ...base,
    ...cookieArgs(cookiesPath),
  ]

  const errors: string[] = []

  try {
    return await runProbe(
      [...noCookieBase, url],
      30_000
    )
  } catch (e) {
    errors.push(
      e instanceof Error
        ? e.message
        : String(e)
    )
  }

  if (cookiesPath) {
    try {
      return await runProbe(
        [...withCookieBase, url],
        45_000
      )
    } catch (e) {
      errors.push(
        e instanceof Error
          ? e.message
          : String(e)
      )
    }
  }

  if (await canImpersonate()) {
    try {
      return await runProbe(
        [
          ...withCookieBase,
          "--impersonate",
          "chrome",
          url,
        ],
        45_000
      )
    } catch (e) {
      errors.push(
        e instanceof Error
          ? e.message
          : String(e)
      )
    }
  }

  try {
    return await runProbe(
      [
        ...withCookieBase,
        "--force-generic-extractor",
        url,
      ],
      45_000
    )
  } catch (e) {
    errors.push(
      e instanceof Error
        ? e.message
        : String(e)
    )
  }

  const candidates =
    await scanPageForMedia(url)

  const embed = candidates.find(
    (c) => c.kind === "embed"
  )

  if (embed) {
    try {
      return await runProbe(
        [
          ...withCookieBase,
          embed.url,
        ],
        60_000
      )
    } catch (e) {
      errors.push(
        e instanceof Error
          ? e.message
          : String(e)
      )
    }
  }

  if (candidates.length) {
    const html =
      await fetchPage(url)

    const title =
      /<title[^>]*>([^<]{1,200})/i.exec(
        html
      )?.[1]?.trim()

    const thumb =
      /<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i.exec(
        html
      )?.[1]

    return {
      id: crypto.randomUUID(),
      title: title || url,
      thumbnail: thumb ?? null,
      duration: null,
      webpage_url: url,
      _magica_page_scan: true,
      formats: candidates
        .filter(
          (c) => c.kind !== "embed"
        )
        .map((c) => ({
          url: c.url,
          ext:
            c.kind === "hls"
              ? "mp4"
              : c.kind === "dash"
                ? "mp4"
                : "mp4",
          format_id:
            `page-${c.kind}`,
          format_note:
            `Scanned ${c.kind} URL`,
          height: null,
          width: null,
          filesize: null,
        })),
    }
  }

  const joined =
    errors.join(" || ")

  const failure =
    classifyFailure(joined)

  const err = new Error(
    failure.message
  ) as Error & {
    failure: ExtractionFailure
  }

  err.failure = {
    ...failure,
    detail: joined.slice(0, 900),
  }

  throw err
}

// ---------------------------------------------------------------------------
// Download with fallbacks
// ---------------------------------------------------------------------------

export interface DownloadSuccess {
  filename: string
  sizeBytes: number
  method: string
  durationSec?: number
}

export async function downloadWithFallbacks(
  opts: {
    url: string
    dir: string
    formatArgs: string[]
    cookiesPath: string | null
    infoJsonPath?: string | null
    audioOnly?: boolean
    deadlineMs?: number
  }
): Promise<DownloadSuccess> {
  const {
    url,
    dir,
    formatArgs,
    cookiesPath,
    infoJsonPath,
    audioOnly,
  } = opts

  const deadlineMs =
    opts.deadlineMs ?? 90_000

  const startTime = Date.now()

  const timeLeft = () =>
    deadlineMs -
    (Date.now() - startTime)

  const isYouTube =
    platformKey(url) === "youtube"

  const ytArgs = isYouTube
    ? [
        ...youtubeArgs(),
        ...poTokenArgs(),
      ]
    : []

  const base = [
    "--no-playlist",
    "--no-warnings",
    "--user-agent",
    BROWSER_UA,
    ...ytArgs,
  ]

  const noCookieBase = [...base]

  const withCookieBase = [
    ...base,
    ...cookieArgs(cookiesPath),
  ]

  const errors: string[] = []

  async function wipeDir(
    d: string
  ) {
    const items =
      await fs
        .readdir(d)
        .catch(
          () => [] as string[]
        )

    for (const f of items) {
      await fs
        .rm(
          path.join(d, f),
          {
            recursive: true,
            force: true,
          }
        )
        .catch(() => {})
    }
  }

  async function wipeDirExcept(
    d: string,
    keep: string
  ) {
    const items =
      await fs
        .readdir(d)
        .catch(
          () => [] as string[]
        )

    for (const f of items) {
      if (f === keep) continue

      await fs
        .rm(
          path.join(d, f),
          {
            recursive: true,
            force: true,
          }
        )
        .catch(() => {})
    }
  }

  async function tryAttempt(
    method: string,
    args: string[],
    timeout: number,
    allowVideoOnly: boolean
  ): Promise<DownloadSuccess | null> {
    if (timeLeft() < 5_000) {
      return null
    }

    const actualTimeout =
      Math.min(
        timeout,
        timeLeft() - 2_000
      )

    if (actualTimeout <= 0) {
      return null
    }

    try {
      await execFileAsync(
        "yt-dlp",
        [
          ...args,
          "-o",
          path.join(
            dir,
            "%(title)s.%(ext)s"
          ),
          "--max-filesize",
          MAX_FILESIZE,
        ],
        {
          timeout: actualTimeout,
        }
      )
    } catch (e) {
      errors.push(
        `${method}: ${
          e instanceof Error
            ? e.message
            : String(e)
        }`
      )

      return null
    }

    const items =
      await fs
        .readdir(dir)
        .catch(
          () => [] as string[]
        )

    const media =
      items.filter(
        (f) =>
          !f.startsWith(".") &&
          !f.endsWith(".json") &&
          !f.endsWith(".part")
      )

    if (!media.length) {
      errors.push(
        `${method}: no output file produced`
      )

      return null
    }

    // FIX:
    // Resolve every fs.stat() first so size is a number,
    // not Promise<number>.
    const stats =
      await Promise.all(
        media.map(
          async (name) => {
            try {
              const stat =
                await fs.stat(
                  path.join(
                    dir,
                    name
                  )
                )

              return {
                name,
                size: stat.size,
              }
            } catch {
              return {
                name,
                size: 0,
              }
            }
          }
        )
      )

    const best =
      stats.sort(
        (a, b) =>
          b.size - a.size
      )[0]

    if (!best) {
      errors.push(
        `${method}: could not determine best output file`
      )

      return null
    }

    const check =
      await validateMediaFile(
        path.join(
          dir,
          best.name
        )
      )

    if (!check.ok) {
      errors.push(
        `${method}: rejected fake media (${check.reason})`
      )

      await wipeDir(dir)

      return null
    }

    if (
      !audioOnly &&
      check.hasVideo &&
      !check.hasAudio &&
      !allowVideoOnly
    ) {
      errors.push(
        `${method}: rejected video-only output (missing audio track)`
      )

      await fs
        .rm(
          path.join(
            dir,
            best.name
          ),
          {
            force: true,
          }
        )
        .catch(() => {})

      return null
    }

    if (
      audioOnly &&
      !check.hasAudio
    ) {
      errors.push(
        `${method}: rejected output without audio stream`
      )

      await fs
        .rm(
          path.join(
            dir,
            best.name
          ),
          {
            force: true,
          }
        )
        .catch(() => {})

      return null
    }

    return {
      filename: best.name,
      sizeBytes: best.size,
      method,
      durationSec:
        check.durationSec,
    }
  }

  const sourceHasNoAudio =
    await (async (): Promise<boolean> => {
      if (!infoJsonPath) {
        return false
      }

      try {
        const raw = JSON.parse(
          await fs.readFile(
            infoJsonPath,
            "utf8"
          )
        )

        const formats: Array<{
          acodec?: string
        }> =
          Array.isArray(raw?.formats)
            ? raw.formats
            : []

        if (
          formats.length === 0
        ) {
          return false
        }

        return formats.every(
          (f) =>
            !f.acodec ||
            f.acodec === "none"
        )
      } catch {
        return false
      }
    })()

  const robust = (
    baseArgs: string[]
  ) =>
    formatArgs[0] === "-f"
      ? [
          "-f",
          `${formatArgs[1]}/best/worst`,
          ...formatArgs.slice(2),
          ...baseArgs,
        ]
      : [
          ...formatArgs,
          ...baseArgs,
        ]

  if (infoJsonPath) {
    const r0 =
      await tryAttempt(
        "cached-info-json",
        [
          ...robust(
            noCookieBase
          ),
          "--load-info-json",
          infoJsonPath,
        ],
        10 * 60 * 1000,
        sourceHasNoAudio
      )

    if (r0) {
      return r0
    }
  }

  let r =
    await tryAttempt(
      "native",
      [
        ...robust(
          noCookieBase
        ),
        url,
      ],
      20 * 60 * 1000,
      sourceHasNoAudio
    )

  if (r) {
    return r
  }

  if (cookiesPath) {
    r = await tryAttempt(
      "native-cookie",
      [
        ...robust(
          withCookieBase
        ),
        url,
      ],
      15 * 60 * 1000,
      sourceHasNoAudio
    )

    if (r) {
      return r
    }
  }

  if (await canImpersonate()) {
    r = await tryAttempt(
      "impersonate",
      [
        ...robust(
          withCookieBase
        ),
        "--impersonate",
        "chrome",
        url,
      ],
      15 * 60 * 1000,
      sourceHasNoAudio
    )

    if (r) {
      return r
    }
  }

  r = await tryAttempt(
    "generic",
    [
      ...robust(
        withCookieBase
      ),
      "--force-generic-extractor",
      url,
    ],
    10 * 60 * 1000,
    sourceHasNoAudio
  )

  if (r) {
    return r
  }

  const candidates =
    await scanPageForMedia(url)
      .catch(
        () =>
          [] as MediaCandidate[]
      )

  let decoyFallback:
    DownloadSuccess | null =
      null

  for (const c of candidates) {
    if (timeLeft() < 30_000) {
      break
    }

    const fmt =
      c.kind === "direct"
        ? audioOnly
          ? formatArgs
          : []
        : robust([])

    const refArgs =
      c.kind === "embed"
        ? []
        : [
            "--referer",
            c.referer,
          ]

    r = await tryAttempt(
      `page-scan:${c.kind}`,
      [
        ...fmt,
        ...withCookieBase,
        ...refArgs,
        c.url,
      ],
      8 * 60 * 1000,
      sourceHasNoAudio
    )

    if (r) {
      const suspicious =
        (r.durationSec ?? 0) <
          15 &&
        r.sizeBytes <
          5_000_000

      if (!suspicious) {
        return r
      }

      if (
        !decoyFallback ||
        r.sizeBytes >
          decoyFallback.sizeBytes
      ) {
        const kept =
          path.join(
            dir,
            ".keep-" +
              r.filename
          )

        await fs
          .rename(
            path.join(
              dir,
              r.filename
            ),
            kept
          )
          .catch(() => {})

        decoyFallback = {
          ...r,
          filename:
            ".keep-" +
            r.filename,
        }
      }

      await wipeDirExcept(
        dir,
        decoyFallback.filename
      )
    }
  }

  if (decoyFallback) {
    const finalName =
      decoyFallback.filename.replace(
        /^\.keep-/,
        ""
      )

    await fs
      .rename(
        path.join(
          dir,
          decoyFallback.filename
        ),
        path.join(
          dir,
          finalName
        )
      )
      .catch(() => {})

    return {
      ...decoyFallback,
      filename: finalName,
      method:
        decoyFallback.method +
        ":short",
    }
  }

  const joined =
    errors.join(" || ")

  const failure =
    classifyFailure(joined)

  const err = new Error(
    failure.message
  ) as Error & {
    failure: ExtractionFailure
  }

  err.failure = {
    ...failure,
    detail:
      joined.slice(0, 900),
  }

  throw err
}

export { UnsafeUrlError }
