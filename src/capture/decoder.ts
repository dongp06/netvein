import * as fs from "node:fs";
import * as zlib from "node:zlib";
import type { InspectBodyResult, StreamEvent } from "./types.js";

function tryDecompress(buf: Buffer): { buffer: Buffer; encoding?: string; decompressed: boolean } {
  // Check gzip magic bytes 0x1f 0x8b
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    try {
      return { buffer: zlib.gunzipSync(buf), encoding: "gzip", decompressed: true };
    } catch {
      // failed decompression, return original
    }
  }

  // Check zlib deflate magic bytes 0x78 0x9c / 0x78 0x01 / 0x78 0xda
  if (buf.length >= 2 && buf[0] === 0x78 && (buf[1] === 0x9c || buf[1] === 0x01 || buf[1] === 0xda)) {
    try {
      return { buffer: zlib.inflateSync(buf), encoding: "deflate", decompressed: true };
    } catch {
      // fallback
    }
  }

  // Try brotli decompression if plausible
  try {
    const unbrotli = zlib.brotliDecompressSync(buf);
    if (unbrotli.length > buf.length) {
      return { buffer: unbrotli, encoding: "br", decompressed: true };
    }
  } catch {
    // not brotli
  }

  return { buffer: buf, decompressed: false };
}

function formatHex(buf: Buffer, maxBytes = 4096): string {
  const slice = buf.subarray(0, maxBytes);
  const lines: string[] = [];

  for (let i = 0; i < slice.length; i += 16) {
    const chunk = slice.subarray(i, i + 16);
    const hexParts: string[] = [];
    let asciiPart = "";

    for (let j = 0; j < 16; j++) {
      if (j < chunk.length) {
        const byte = chunk[j];
        hexParts.push(byte.toString(16).padStart(2, "0"));
        asciiPart += byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".";
      } else {
        hexParts.push("  ");
      }
    }

    const offsetStr = i.toString(16).padStart(8, "0");
    lines.push(`${offsetStr}  ${hexParts.slice(0, 8).join(" ")}  ${hexParts.slice(8).join(" ")}  |${asciiPart}|`);
  }

  if (buf.length > maxBytes) {
    lines.push(`... [${buf.length - maxBytes} more bytes]`);
  }

  return lines.join("\n");
}

export function inspectBody(options: {
  filePath?: string;
  rawBase64?: string;
  format?: "json" | "text" | "hex" | "base64";
  maxChars?: number;
}): InspectBodyResult {
  let rawBuf: Buffer;
  let targetPath: string | undefined;

  if (options.filePath && fs.existsSync(options.filePath)) {
    rawBuf = fs.readFileSync(options.filePath);
    targetPath = options.filePath;
  } else if (options.rawBase64) {
    rawBuf = Buffer.from(options.rawBase64, "base64");
  } else {
    throw new Error("Either filePath or rawBase64 must be provided.");
  }

  const { buffer, encoding, decompressed } = tryDecompress(rawBuf);
  const requestedFormat = options.format || "text";
  const maxChars = options.maxChars ?? 20000;

  let content = "";
  let finalFormat: "json" | "text" | "hex" | "base64" = requestedFormat;

  if (requestedFormat === "hex") {
    content = formatHex(buffer, Math.floor(maxChars / 4));
  } else if (requestedFormat === "base64") {
    content = buffer.toString("base64");
  } else {
    // text or json
    const text = buffer.toString("utf8");
    if (requestedFormat === "json") {
      try {
        const parsed = JSON.parse(text);
        content = JSON.stringify(parsed, null, 2);
        finalFormat = "json";
      } catch {
        content = text;
        finalFormat = "text";
      }
    } else {
      // If user requested text, but it's valid JSON, keep as text
      content = text;
    }
  }

  if (content.length > maxChars) {
    content = content.slice(0, maxChars) + "\n... [truncated]";
  }

  return {
    path: targetPath,
    sizeBytes: rawBuf.length,
    decompressed,
    encoding,
    format: finalFormat,
    content,
  };
}

export function parseSseStream(text: string): StreamEvent[] {
  const lines = text.split(/\r?\n/);
  const events: StreamEvent[] = [];
  let currentEvent: { event?: string; id?: string; data: string[]; raw: string[] } | null = null;
  let idx = 0;

  const flush = () => {
    if (!currentEvent || (currentEvent.data.length === 0 && !currentEvent.event)) return;
    const combinedData = currentEvent.data.join("\n").trim();
    let parsedData: unknown = combinedData;

    try {
      parsedData = JSON.parse(combinedData);
    } catch {
      // keep raw string
    }

    events.push({
      index: idx++,
      event: currentEvent.event,
      id: currentEvent.id,
      data: parsedData,
      raw: currentEvent.raw.join("\n"),
    });
    currentEvent = null;
  };

  for (const line of lines) {
    if (!line.trim()) {
      flush();
      continue;
    }

    if (!currentEvent) {
      currentEvent = { data: [], raw: [] };
    }
    currentEvent.raw.push(line);

    if (line.startsWith(":")) {
      // SSE comment / heartbeat
      continue;
    }

    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) {
      continue;
    }

    const field = line.slice(0, colonIdx).trim();
    const value = line.slice(colonIdx + 1).replace(/^ /, "");

    if (field === "event") {
      currentEvent.event = value;
    } else if (field === "id") {
      currentEvent.id = value;
    } else if (field === "data") {
      currentEvent.data.push(value);
    }
  }

  flush();
  return events;
}

export function parseAwsEventStream(buf: Buffer): StreamEvent[] {
  const events: StreamEvent[] = [];
  let offset = 0;
  let idx = 0;

  while (offset + 16 <= buf.length) {
    const totalLen = buf.readUInt32BE(offset);
    const headersLen = buf.readUInt32BE(offset + 4);

    if (totalLen < 16 || offset + totalLen > buf.length) {
      break;
    }

    const headers: Record<string, string> = {};
    let hOffset = offset + 12;
    const hEnd = offset + 12 + headersLen;

    while (hOffset < hEnd && hOffset < buf.length) {
      const nameLen = buf[hOffset];
      hOffset++;
      const name = buf.toString("utf8", hOffset, hOffset + nameLen);
      hOffset += nameLen;
      const type = buf[hOffset];
      hOffset++;

      if (type === 7) {
        // String value (length uint16)
        const vLen = buf.readUInt16BE(hOffset);
        hOffset += 2;
        headers[name] = buf.toString("utf8", hOffset, hOffset + vLen);
        hOffset += vLen;
      } else {
        headers[name] = `<type ${type}>`;
        break;
      }
    }

    const payloadStart = offset + 12 + headersLen;
    const payloadEnd = offset + totalLen - 4; // Minus 4 bytes message CRC
    let payloadStr = "";
    let parsedPayload: unknown = null;

    if (payloadEnd > payloadStart) {
      payloadStr = buf.toString("utf8", payloadStart, payloadEnd);
      try {
        parsedPayload = JSON.parse(payloadStr);
      } catch {
        parsedPayload = payloadStr;
      }
    }

    events.push({
      index: idx++,
      event: headers[":event-type"] || headers[":message-type"] || headers[":exception-type"],
      id: headers[":content-type"],
      data: parsedPayload,
      raw: payloadStr,
    });

    offset += totalLen;
  }

  return events;
}
