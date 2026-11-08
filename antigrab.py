"""
antigrab.py - deteção de token grabbers / exfiltração de credenciais em scripts.

Puro Python (sem discord.py), para poder ser testado à parte.
Uso:
    from antigrab import scan, redact_text, redact_bytes
    r = scan(codigo)           # r.level in ("clean", "info", "suspicious", "blocked")
    r.score, r.findings        # pontuação 0-100 e lista de achados
"""
import re
from dataclasses import dataclass, field

BLOCK_THRESHOLD = 60   # >= bloqueia
WARN_THRESHOLD = 25    # >= suspeito (avisa, mas não bloqueia por si só)
MAX_SCAN_CHARS = 6_000_000

_TOKEN = r'(?<![\w-])(?:[\w-]{23,28}\.[\w-]{6}\.[\w-]{25,110}|mfa\.[\w-]{80,95})(?![\w-])'
TOKEN_RE = re.compile(_TOKEN)
WEBHOOK_RE = re.compile(
    r'(https?://(?:[\w-]+\.)*discord(?:app)?\.com/api/(?:v\d+/)?webhooks/)(\d{15,25})/([\w-]{20,})',
    re.IGNORECASE,
)

# (peso, rótulo, regex)
RULES = [
    (60, "Discord token pattern", TOKEN_RE),
    (50, "Discord token storage (leveldb / Local Storage)",
     re.compile(r'(?i)discord(?:canary|ptb|development)?[\\/ ]+(?:Local Storage|leveldb)|Local Storage[\\/]+leveldb')),
    (45, "Encrypted token marker (dQw4w9WgXcQ:)", re.compile(r'dQw4w9WgXcQ:')),
    (35, "Discord API account lookup (/users/@me)",
     re.compile(r'(?i)discord(?:app)?\.com/api/(?:v\d+/)?users/@me')),
    (25, "Roblox cookie (.ROBLOSECURITY)",
     re.compile(r'(?i)\.ROBLOSECURITY|_\|WARNING:-DO-NOT-SHARE-THIS')),
    (20, "Browser credential paths",
     re.compile(r'(?i)Login Data|Web Data|User Data[\\/]+Default|BraveSoftware|Opera Software|Google[\\/]+Chrome[\\/]+User')),
    (20, "Discord webhook (data exfiltration channel)", WEBHOOK_RE),
    (15, "AppData access",
     re.compile(r'(?i)%APPDATA%|%LOCALAPPDATA%|getenv\(\s*["\']?(?:APPDATA|LOCALAPPDATA)|os\.environ\[["\']?(?:APPDATA|LOCALAPPDATA)')),
    (15, "Shell / process execution",
     re.compile(r'(?i)\b(?:os\.execute|io\.popen|child_process|subprocess|powershell(?:\.exe)?|cmd\.exe|WScript\.Shell)\b')),
    (10, "Authorization header",
     re.compile(r'(?i)["\']Authorization["\']\s*[:=,\]]')),
]

_DEC_ESC = re.compile(r'\\(\d{1,3})')
_HEX_ESC = re.compile(r'\\x([0-9a-fA-F]{2})')


@dataclass
class Finding:
    label: str
    weight: int
    sample: str = ""


@dataclass
class ScanResult:
    score: int = 0
    findings: list = field(default_factory=list)

    @property
    def level(self) -> str:
        if self.score >= BLOCK_THRESHOLD:
            return "blocked"
        if self.score >= WARN_THRESHOLD:
            return "suspicious"
        if self.findings:
            return "info"
        return "clean"


def mask_token(tok: str) -> str:
    return tok[:6] + "••••••••"


def mask_webhook(url: str) -> str:
    m = WEBHOOK_RE.search(url)
    if not m:
        return url[:40]
    return f"{m.group(1)}{m.group(2)}/{m.group(3)[:4]}••••"


def redact_text(text: str) -> str:
    """Esconde tokens do Discord e a parte secreta de webhooks."""
    text = TOKEN_RE.sub(lambda m: mask_token(m.group(0)), text)
    text = WEBHOOK_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}/{m.group(3)[:4]}••••", text)
    return text


def redact_bytes(data: bytes) -> bytes:
    return redact_text(data.decode("utf-8", "replace")).encode("utf-8")


def _unescape(text: str) -> str:
    """Decodifica \\104\\116... e \\x68... (muito usado por ofuscadores)."""
    text = _DEC_ESC.sub(lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), text)
    return _HEX_ESC.sub(lambda m: chr(int(m.group(1), 16)), text)


def _sample(label: str, match: re.Match) -> str:
    raw = match.group(0)
    if "token pattern" in label:
        return mask_token(raw)
    if "webhook" in label.lower():
        return mask_webhook(raw)
    return raw[:48].replace("\n", " ")


def scan(text) -> ScanResult:
    if isinstance(text, bytes):
        text = text.decode("utf-8", "ignore")
    text = text[:MAX_SCAN_CHARS]
    corpus = text
    if "\\" in text and len(_DEC_ESC.findall(text[:200000])) > 20:
        corpus = text + "\n" + _unescape(text)
    result = ScanResult()
    total = 0
    for weight, label, rx in RULES:
        m = rx.search(corpus)
        if m:
            total += weight
            result.findings.append(Finding(label, weight, _sample(label, m)))
    result.score = min(100, total)
    return result
