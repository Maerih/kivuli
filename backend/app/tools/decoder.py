"""Peel obfuscation off a script or payload, layer by layer. Never runs it.

Malware droppers, phishing pages and loader one-liners hide what they do behind
encodings. This undoes the common ones, repeatedly, and shows each layer:

  PowerShell -EncodedCommand (base64 of UTF-16LE), base64, hex (plain, \\x, 0x),
  URL encoding, gzip / zlib / raw deflate, character-code arrays
  (String.fromCharCode, [char]NN, chr(NN)), \\u and \\x escapes inside strings,
  reversed strings, ROT13, and base64 blobs embedded in a larger script
  (FromBase64String('...'), atob("..."), long literals).

Every step is a pure transformation with a hard output cap, so a decompression
bomb or a pathological input cannot exhaust memory. The result is text to read,
plus the indicators and the behaviours (download, execute, persistence...) that
the decoded text mentions.
"""
import base64
import binascii
import re
import zlib
from urllib.parse import unquote

from app.extract.iocs import extract_iocs, refang

MAX_INPUT = 512_000
MAX_LAYER = 2_000_000
MAX_DEPTH = 12

_B64 = re.compile(r"^[A-Za-z0-9+/=\s_-]+$")
_PS_ENC = re.compile(r"-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+['\"]?([A-Za-z0-9+/=]{16,})", re.I)
_B64_CALL = re.compile(r"(?:FromBase64String|atob|base64_decode|b64decode|DecodeBase64|base64\s+-d)\s*\(?\s*['\"]([A-Za-z0-9+/=_-]{8,})['\"]", re.I)
_B64_LITERAL = re.compile(r"['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]")
_HEX = re.compile(r"^(?:\s*(?:0x|\\x)?[0-9a-fA-F]{2}[\s,]*)+$")
_CHARCODES = re.compile(r"(?:fromCharCode\s*\(|\[char\]\s*|chr\w?\s*\(|ChrW?\s*\()\s*(\d{2,3})", re.I)
_CHARCODE_LIST = re.compile(r"(?:String\s*\.\s*)?fromCharCode\s*\(\s*([\d,\s]+)\)", re.I)
_ESCAPES = re.compile(r"(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}){4,}")
_URLENC = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")

BEHAVIOURS = [
    ("download", r"DownloadString|DownloadFile|DownloadData|Net\.WebClient|Invoke-WebRequest|\biwr\b|Start-BitsTransfer|bitsadmin|curl\s|wget\s|XMLHTTP|WinHttpRequest|fetch\(|urllib|requests\.get", "Downloads something"),
    ("execute", r"Invoke-Expression|\bIEX\b|Start-Process|WScript\.Shell|Shell\.Application|cmd(?:\.exe)?\s+/c|\beval\s*\(|exec\s*\(|subprocess|os\.system|Runtime\.getRuntime|\|\s*(?:ba)?sh\b|powershell\s", "Runs code or commands"),
    ("lolbin", r"\bmshta\b|\bregsvr32\b|\brundll32\b|\bcertutil\b|\bmsiexec\b|\bwmic\b|\bcscript\b|\bwscript\b|\bInstallUtil\b|\bmsbuild\b", "Uses a built-in Windows binary to run code"),
    ("persistence", r"CurrentVersion\\\\?Run|schtasks|New-ScheduledTask|Register-ScheduledTask|crontab|systemctl\s+enable|Startup\\\\|New-Service|sc\s+create", "Sets up persistence"),
    ("defence_evasion", r"Set-MpPreference|DisableRealtimeMonitoring|AmsiUtils|amsiInitFailed|-ExecutionPolicy\s+Bypass|-ep\s+bypass|-w(?:indowstyle)?\s+hidden|-nop\b|Add-MpPreference\s+-ExclusionPath", "Tries to avoid detection"),
    ("injection", r"VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|Reflection\.Assembly\]::Load|\[System\.Runtime\.InteropServices", "Loads or injects code in memory"),
    ("credentials", r"mimikatz|sekurlsa|lsass|Get-Credential|password\s*=|SAM\b.*SYSTEM|vaultcmd|\.kdbx", "Touches credentials"),
    ("browser", r"document\.write|window\.location|location\.href|\.submit\(\)|ActiveXObject|<iframe", "Redirects or writes a page"),
]


def _printable(data: str) -> float:
    if not data:
        return 0.0
    good = sum(1 for c in data if c.isprintable() or c in "\r\n\t")
    return good / len(data)


def _text(raw: bytes) -> str | None:
    """Bytes as text if they look like text: UTF-16LE (PowerShell) or UTF-8/latin-1."""
    if len(raw) >= 4 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00":
        try:
            t = raw.decode("utf-16-le")
            if _printable(t) > 0.9:
                return t
        except UnicodeDecodeError:
            pass
    try:
        t = raw.decode("utf-8")
        if _printable(t) > 0.85:
            return t
    except UnicodeDecodeError:
        pass
    # Latin-1 decodes any bytes at all, so it only counts when the result is mostly plain ASCII.
    t = raw.decode("latin-1")
    if t and _printable(t) > 0.85 and sum(1 for c in t if ord(c) < 128) / len(t) > 0.9:
        return t
    return None


def _inflate(raw: bytes) -> tuple[str, bytes] | None:
    for name, wbits in (("gzip", 31), ("zlib", 15), ("raw deflate", -15)):
        d = zlib.decompressobj(wbits)
        try:
            out = d.decompress(raw, MAX_LAYER)
        except zlib.error:
            continue
        if out:
            return name, out
    return None


def _b64(value: str, minimum: int = 16) -> bytes | None:
    s = re.sub(r"\s+", "", value)
    if len(s) < minimum:
        return None
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def _bytes_layer(name: str, raw: bytes) -> tuple[str, str] | None:
    """Turn decoded bytes into the next layer, decompressing if they are compressed."""
    if raw[:2] == b"\x1f\x8b" or raw[:1] == b"\x78" or _text(raw) is None:
        inflated = _inflate(raw)
        if inflated:
            text = _text(inflated[1])
            if text is not None:
                return f"{name}, then {inflated[0]} decompression", text
    text = _text(raw)
    return (name, text) if text is not None else None


def _step(data: str) -> tuple[str, str] | None:
    """One decoding step: the first transformation that makes the text more readable."""
    stripped = data.strip()

    if m := _PS_ENC.search(stripped):
        raw = _b64(m.group(1))
        if raw and (layer := _bytes_layer("PowerShell -EncodedCommand (base64, UTF-16LE)", raw)):
            return layer

    if len(stripped) >= 16 and _B64.match(stripped) and not _HEX.match(stripped):
        raw = _b64(stripped)
        if raw and (layer := _bytes_layer("Base64", raw)):
            return layer

    if len(stripped) >= 8 and _HEX.match(stripped):
        digits = re.sub(r"0x|\\x|[\s,]", "", stripped)
        # Hex-encoded text always has digits 2-7 (the high nibble of printable ASCII); "AAAA..." is not hex.
        if len(digits) % 2 == 0 and re.search(r"[2-7]", digits):
            try:
                raw = bytes.fromhex(digits)
            except ValueError:
                raw = b""
            if raw and (layer := _bytes_layer("Hex", raw)):
                return layer

    # A decoding call is replaced in place, so the script around it stays readable.
    for m in list(_B64_CALL.finditer(data)) or sorted(_B64_LITERAL.finditer(data), key=lambda x: -len(x.group(1)))[:1]:
        raw = _b64(m.group(1), minimum=8)
        if raw and (layer := _bytes_layer("Embedded base64", raw)):
            return f"{layer[0]} (from {m.group(0)[:40]}…)", data[: m.start()] + repr(layer[1]) + data[m.end():]

    if (m := _CHARCODE_LIST.search(data)):
        try:
            chars = "".join(chr(int(n)) for n in re.findall(r"\d+", m.group(1)) if int(n) < 0x110000)
        except ValueError:
            chars = ""
        if len(chars) >= 4:
            return "String.fromCharCode array", data[: m.start()] + repr(chars) + data[m.end():]
    codes = _CHARCODES.findall(data)
    if len(codes) >= 6:
        return "Character codes ([char]NN / chr(NN))", "".join(chr(int(n)) for n in codes if int(n) < 0x110000)

    if _ESCAPES.search(data):
        def unescape(m):
            return m.group(0).encode("ascii").decode("unicode_escape", "replace")
        return "\\u / \\x escapes", _ESCAPES.sub(unescape, data)

    if len(_URLENC.findall(data)) >= 1 and data.count("%") >= 6:
        decoded = unquote(data)
        if decoded != data:
            return "URL encoding", decoded

    reversed_text = data[::-1]
    if re.search(r"ptth|llehsrewop|xei\b|gnirtsdaolnwod", data, re.I) and re.search(r"http|powershell|iex|downloadstring", reversed_text, re.I):
        return "Reversed string", reversed_text

    rot = data.translate(_ROT13)
    if not re.search(r"https?://|powershell|function|eval|var |\bif\b", data, re.I) and re.search(r"https?://|powershell|function|eval\(", rot, re.I):
        return "ROT13", rot
    return None


_ROT13 = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")


def behaviours(text: str) -> list[dict]:
    out = []
    for key, pattern, label in BEHAVIOURS:
        found = sorted({m.group(0).strip() for m in re.finditer(pattern, text, re.I)})
        if found:
            out.append({"key": key, "label": label, "evidence": found[:8]})
    return out


def decode(text: str) -> dict:
    data = (text or "")[:MAX_INPUT]
    if not data.strip():
        return {"ok": False, "error": "Paste a script, command line or encoded payload."}
    layers = [{"step": "Input", "text": data[:20000], "length": len(data)}]
    seen = {data}
    for _ in range(MAX_DEPTH):
        nxt = _step(data)
        if nxt is None:
            break
        name, out = nxt
        out = out[:MAX_LAYER]
        if out in seen or not out.strip():
            break
        seen.add(out)
        layers.append({"step": name, "text": out[:20000], "length": len(out)})
        data = out
    everything = refang("\n".join(seen))
    indicators, _ = extract_iocs(everything)
    return {
        "ok": True, "decoded": len(layers) > 1, "layers": layers, "final": data[:200000],
        "behaviours": behaviours("\n".join(seen)),
        "indicators": [{"type": i.type, "value": i.value} for i in indicators][:300],
    }
