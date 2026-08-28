import { execFile } from "child_process"
import { promisify } from "util"
import { existsSync } from "fs"
import path from "path"
import os from "os"

export const execFileAsync = promisify(execFile)

function findProjectRoot(): string {
  const candidates = [
    process.cwd(),
    __dirname.replace(/\/lib$/, ""),
  ]
  for (const c of candidates) {
    if (existsSync(path.join(c, "next.config.js")) || existsSync(path.join(c, "next.config.ts"))) {
      return c
    }
  }
  return process.cwd()
}

export const PROJECT_ROOT = findProjectRoot()
export const DOWNLOAD_ROOT = path.join(PROJECT_ROOT, "downloads")

export const MAX_FILESIZE = "5G"
export const MAX_FILESIZE_BYTES = 5 * 1024 * 1024 * 1024

export function cookieArgs(cookiesPath: string | null | undefined): string[] {
  return cookiesPath && existsSync(cookiesPath) ? ["--cookies", cookiesPath] : []
}

export function isValidUrl(input: string): boolean {
  try {
    const u = new URL(input)
    return u.protocol === "http:" || u.protocol === "https:"
  } catch {
    return false
  }
}

export type PlatformKey =
  | "youtube"
  | "tiktok"
  | "instagram"
  | "twitter"
  | "facebook"
  | "linkedin"
  | "vimeo"
  | "reddit"
  | "other"

export const PLATFORM_LABELS: Record<PlatformKey, string> = {
  youtube: "YouTube",
  tiktok: "TikTok",
  instagram: "Instagram",
  twitter: "X / Twitter",
  facebook: "Facebook",
  linkedin: "LinkedIn",
  vimeo: "Vimeo",
  reddit: "Reddit",
  other: "Other sites",
}

export const PLATFORM_KEYS = Object.keys(PLATFORM_LABELS) as PlatformKey[]

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "").replace(/^m\./, "")
  } catch {
    return ""
  }
}

export function platformKey(url: string): PlatformKey {
  const host = hostOf(url)
  if (/youtube\.com|youtu\.be/.test(host)) return "youtube"
  if (/tiktok\.com/.test(host)) return "tiktok"
  if (/instagram\.com/.test(host)) return "instagram"
  if (/twitter\.com|x\.com/.test(host)) return "twitter"
  if (/facebook\.com|fb\.watch/.test(host)) return "facebook"
  if (/linkedin\.com/.test(host)) return "linkedin"
  if (/vimeo\.com/.test(host)) return "vimeo"
  if (/reddit\.com/.test(host)) return "reddit"
  return "other"
}

export function detectPlatform(url: string): string {
  return PLATFORM_LABELS[platformKey(url)] || "Other sites"
}

// ---------------------------------------------------------------------------
// PO Token provider args (YouTube server-side extraction)
// ---------------------------------------------------------------------------
export function poTokenArgs(): string[] {
  const scriptPath =
    process.env.PO_PROVIDER_SCRIPT_PATH ||
    path.join(os.homedir(), "bgutil-ytdlp-pot-provider", "server", "build", "main.js")
  if (!existsSync(scriptPath)) return []
  return [
    "--extractor-args",
    "youtube:po_token_provider=bgutil-ytdlp-pot-provider",
    "--extractor-args",
    `youtube:po_token_provider_path=${scriptPath}`,
  ]
}

// ---------------------------------------------------------------------------
// YouTube-specific extractor args (reduce bot detection)
// ---------------------------------------------------------------------------
export function youtubeArgs(): string[] {
  return [
    "--extractor-args",
    "youtube:player_client=web",
    "--extractor-args",
    "youtube:player_skip=webpage,configs",
    "--extractor-args",
    "youtube:max_comments=0",
  ]
}

// ---------------------------------------------------------------------------
// Quality presets
// ---------------------------------------------------------------------------
export const QUALITY_MAP: Record<
  string,
  { label: string; args: string[] }
> = {
  best: { label: "Best available", args: ["-f", "bestvideo*+bestaudio/best"] },
  "1080": { label: "1080p", args: ["-f", "bestvideo[height<=1080]+bestaudio/best[height<=1080]"] },
  "720": { label: "720p", args: ["-f", "bestvideo[height<=720]+bestaudio/best[height<=720]"] },
  "480": { label: "480p", args: ["-f", "bestvideo[height<=480]+bestaudio/best[height<=480]"] },
  "360": { label: "360p", args: ["-f", "bestvideo[height<=360]+bestaudio/best[height<=360]"] },
  audio: { label: "Audio only (MP3)", args: ["-f", "bestaudio", "-x", "--audio-format", "mp3"] },
}
