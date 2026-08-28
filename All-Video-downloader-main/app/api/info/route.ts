import { NextRequest, NextResponse } from "next/server"
import { isValidUrl, detectPlatform, platformKey, QUALITY_MAP } from "@/lib/ytdlp"
import { probeWithFallbacks, classifyFailure } from "@/lib/extract"
import { cookiesPathForPlatform, getOrCreateSessionId, SESSION_COOKIE } from "@/lib/session"
import { isSafeToFetch } from "@/lib/security/safe-url"
import { checkRateLimit, clientKey, extractGuard } from "@/lib/security/rate-limit"
import { putResolve } from "@/lib/resolve-cache"
import { VideoInfo } from "@/types"

export const maxDuration = 120

function attachSessionCookie(res: NextResponse, sessionId: string) {
  res.cookies.set(SESSION_COOKIE, sessionId, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 24 * 30,
  })
}

export async function POST(request: NextRequest) {
  console.log("[INFO] ====== NEW REQUEST ======")
  try {
    console.log("[INFO] Step 1: Rate limit check")
    if (!checkRateLimit(`info:${clientKey(request)}`, 20, 60_000)) {
      console.log("[INFO] Rate limited")
      return NextResponse.json({ error: "Too many requests — please slow down and try again in a minute." }, { status: 429 })
    }

    let url = ""
    try {
      console.log("[INFO] Step 2: Parse body")
      const body = await request.json()
      url = String(body?.url ?? "").trim()
      console.log("[INFO] URL:", url)
    } catch (e) {
      console.log("[INFO] Body parse error:", e)
      return NextResponse.json({ error: "Invalid request body" }, { status: 400 })
    }

    if (!isValidUrl(url)) {
      console.log("[INFO] Invalid URL")
      return NextResponse.json({ error: "Please enter a valid http(s) URL" }, { status: 400 })
    }

    console.log("[INFO] Step 3: Safety check")
    const safety = await isSafeToFetch(url)
    if (!safety.ok) {
      console.log("[INFO] Unsafe URL")
      return NextResponse.json({ error: "This URL points to a private/internal address and cannot be fetched." }, { status: 400 })
    }

    console.log("[INFO] Step 4: Acquire guard")
    if (!extractGuard.tryAcquire()) {
      console.log("[INFO] Guard busy")
      return NextResponse.json(
        { error: "The server is busy handling other requests right now — please try again in a few seconds." },
        { status: 503 }
      )
    }

    console.log("[INFO] Step 5: Get session")
    const { sessionId, isNew } = getOrCreateSessionId(request.cookies.get(SESSION_COOKIE)?.value)
    const cookiesPath = cookiesPathForPlatform(sessionId, platformKey(url))
    console.log("[INFO] Session:", sessionId, "isNew:", isNew)

    try {
      console.log("[INFO] Step 6: Probe start")
      const entry = await probeWithFallbacks(url, cookiesPath)
      console.log("[INFO] Step 6: Probe success, title:", entry.title)

      if (!entry) throw new Error("No video found at this URL")

      console.log("[INFO] Step 7: Build response")
      const heights: number[] = Array.isArray(entry.formats)
        ? entry.formats
            .map((f: { height?: number | null }) => f.height ?? 0)
            .filter((h: number) => h > 0)
        : []
      const maxHeight = heights.length ? Math.max(...heights) : 0

      const formats = Object.entries(QUALITY_MAP)
        .filter(([key]) => {
          if (key === "best" || key === "audio") return true
          if (maxHeight === 0) return true
          return parseInt(key) <= maxHeight
        })
        .map(([value, v]) => ({ value, label: v.label }))

      const resolveId = await putResolve(url, cookiesPath, sessionId, entry)

      const info: VideoInfo = {
        id: entry.id ?? crypto.randomUUID(),
        title: entry.title ?? "Untitled video",
        thumbnail: entry.thumbnail ?? null,
        duration: typeof entry.duration === "number" ? entry.duration : null,
        uploader: entry.uploader ?? entry.channel ?? null,
        platform: detectPlatform(url),
        webpageUrl: entry.webpage_url ?? url,
        formats,
        resolveId,
      }

      console.log("[INFO] Step 8: Send success response")
      const res = NextResponse.json(info)
      if (isNew) attachSessionCookie(res, sessionId)
      console.log("[INFO] ====== SUCCESS ======")
      return res
    } catch (err: unknown) {
      console.log("[INFO] Step 6/7: Probe/Build error:", err)
      console.log("[INFO] Error type:", typeof err)
      console.log("[INFO] Error instanceof Error:", err instanceof Error)

      if (err instanceof Error) {
        console.log("[INFO] Error message:", err.message)
        console.log("[INFO] Error has failure?:", 'failure' in err)
        if ('failure' in err) {
          console.log("[INFO] Error.failure:", JSON.stringify((err as any).failure))
        }
      }

      const msg = err instanceof Error ? err.message : "Failed to fetch video info"
      console.log("[INFO] Classifying message:", msg.substring(0, 100))

      let failure
      try {
        failure = classifyFailure(msg, "resolve")
        console.log("[INFO] Classification result:", JSON.stringify(failure))
      } catch (classifyErr) {
        console.log("[INFO] classifyFailure threw:", classifyErr)
        failure = { category: "INTERNAL_ERROR", message: "Request failed due to an internal server error.", detail: msg }
      }

      console.log("[INFO] Step 9: Build error response")
      let res
      try {
        res = NextResponse.json(
          { error: failure.message, category: failure.category, detail: failure.detail },
          { status: 422 }
        )
        console.log("[INFO] Response built successfully")
      } catch (responseErr) {
        console.log("[INFO] NextResponse.json threw:", responseErr)
        return NextResponse.json({ error: "Server error building response" }, { status: 500 })
      }

      if (isNew) {
        console.log("[INFO] Attaching session cookie")
        try {
          attachSessionCookie(res, sessionId)
          console.log("[INFO] Cookie attached")
        } catch (cookieErr) {
          console.log("[INFO] attachSessionCookie threw:", cookieErr)
        }
      }

      console.log("[INFO] ====== RETURNING 422 ======")
      return res
    } finally {
      console.log("[INFO] Releasing guard")
      extractGuard.release()
      console.log("[INFO] Guard released")
    }
  } catch (err: unknown) {
    console.error("[INFO] ====== UNCAUGHT ERROR ======")
    console.error("[INFO] Error:", err)
    const msg = err instanceof Error ? err.message : String(err)
    console.error("[INFO] Message:", msg)
    return NextResponse.json(
      { error: `Server error: ${msg}` },
      { status: 500 }
    )
  }
}
