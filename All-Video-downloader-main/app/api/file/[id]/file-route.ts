import { NextResponse } from "next/server"
import { promises as fs } from "fs"
import { createReadStream } from "fs"
import path from "path"
import { DOWNLOAD_ROOT } from "@/lib/ytdlp"

const MIME: Record<string, string> = {
  ".mp4": "video/mp4",
  ".webm": "video/webm",
  ".mkv": "video/x-matroska",
  ".mp3": "audio/mpeg",
  ".m4a": "audio/mp4",
  ".opus": "audio/ogg",
  ".jpg": "image/jpeg",
  ".png": "image/png",
  ".webp": "image/webp",
}

function nodeStreamToWeb(filePath: string, range?: { start: number; end: number }): ReadableStream<Uint8Array> {
  const nodeStream = range
    ? createReadStream(filePath, { start: range.start, end: range.end, highWaterMark: 1024 * 1024 })
    : createReadStream(filePath, { highWaterMark: 1024 * 1024 })
  let closed = false
  return new ReadableStream<Uint8Array>({
    start(controller) {
      nodeStream.on("data", (chunk: string | Buffer) => {
        if (closed) return
        try {
          controller.enqueue(
            typeof chunk === "string" ? new TextEncoder().encode(chunk) : new Uint8Array(chunk)
          )
          if (controller.desiredSize !== null && controller.desiredSize <= 0) {
            nodeStream.pause()
          }
        } catch {
          closed = true
          nodeStream.destroy()
        }
      })
      nodeStream.on("end", () => {
        if (closed) return
        closed = true
        try {
          controller.close()
        } catch {
          // already closed by the client — ignore
        }
      })
      nodeStream.on("error", (err) => {
        if (closed) return
        closed = true
        try {
          controller.error(err)
        } catch {
          // already closed — ignore
        }
      })
    },
    pull() {
      nodeStream.resume()
    },
    cancel() {
      closed = true
      nodeStream.destroy()
    },
  })
}

function parseRange(header: string, size: number): { start: number; end: number } | null {
  const m = /^bytes=(\d*)-(\d*)$/.exec(header.trim())
  if (!m) return null
  const [, startStr, endStr] = m
  let start: number
  let end: number
  if (startStr === "" && endStr === "") return null
  if (startStr === "") {
    const suffixLen = parseInt(endStr, 10)
    if (Number.isNaN(suffixLen) || suffixLen <= 0) return null
    start = Math.max(0, size - suffixLen)
    end = size - 1
  } else {
    start = parseInt(startStr, 10)
    end = endStr === "" ? size - 1 : parseInt(endStr, 10)
  }
  if (Number.isNaN(start) || Number.isNaN(end) || start > end || start < 0 || start >= size) return null
  end = Math.min(end, size - 1)
  return { start, end }
}

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
    return NextResponse.json({ error: "Invalid file ID" }, { status: 400 })
  }

  const dir = path.join(DOWNLOAD_ROOT, id)
  let files: string[] = []
  try {
    files = await fs.readdir(dir)
  } catch {
    return NextResponse.json({ error: "File not found or expired" }, { status: 404 })
  }

  const media = files.find((f) => !f.startsWith(".") && !f.endsWith(".json") && !f.endsWith(".part"))
  if (!media) {
    return NextResponse.json({ error: "File not ready" }, { status: 404 })
  }

  const filePath = path.join(dir, media)
  let st: import("fs").Stats
  try {
    st = await fs.stat(filePath)
  } catch {
    return NextResponse.json({ error: "File not found" }, { status: 404 })
  }

  const ext = path.extname(media).toLowerCase()
  const mime = MIME[ext] || "application/octet-stream"

  // FIX: Sanitize filename for Content-Disposition (RFC 5987)
  const safeName = media.replace(/["\\]/g, "").replace(/[^\w\s.-]/g, "_")
  const contentDisposition = `attachment; filename="${safeName}"; filename*=UTF-8''${encodeURIComponent(safeName)}`

  const rangeHeader = request.headers.get("range")
  const range = rangeHeader ? parseRange(rangeHeader, st.size) : null

  if (range) {
    const { start, end } = range
    const contentLength = end - start + 1
    return new NextResponse(nodeStreamToWeb(filePath, range), {
      status: 206,
      headers: {
        "Content-Type": mime,
        "Content-Disposition": contentDisposition,
        "Content-Length": String(contentLength),
        "Content-Range": `bytes ${start}-${end}/${st.size}`,
        "Accept-Ranges": "bytes",
        "Cache-Control": "no-store",
      },
    })
  }

  return new NextResponse(nodeStreamToWeb(filePath), {
    headers: {
      "Content-Type": mime,
      "Content-Disposition": contentDisposition,
      "Content-Length": String(st.size),
      "Accept-Ranges": "bytes",
      "Cache-Control": "no-store",
    },
  })
}
