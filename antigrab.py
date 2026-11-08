"""
antigrab.py - deteção de token grabbers / exfiltração de credenciais em scripts.

Puro Python (sem discord.py), para poder ser testado à parte.
Uso:
    from antigrab import scan, redact_text, redact_bytes
    r = scan(codigo)           # r.level in ("clean", "info", "suspicious", "blocked")
    r.score, r.findings        # pontuação 0-100 e lista de achados

Como funciona (resumo):
  1. Normaliza o código: remove caracteres invisíveis, junta "a".."b", table.concat de pedaços,
     decodifica \\104 / \\x68 / \\u{68} / %68.
  2. Procura strings escondidas e decodifica-as (até 3 camadas):
       - listas de números:  string.char(104,116,...)  {104,116,...}  0x68,0x74,...
       - sequências de escapes  "\\104\\116\\116..."
       - blobs base64 / hex / %XX
       - XOR / soma de 1 byte, e XOR com chave repetida (ataque por "crib" em https://discord...)
       - texto invertido (string.reverse)
  3. Aplica as regras ao código original E ao conteúdo decodificado.
     Achados que só aparecem depois de decodificar ganham um bónus (esconder é suspeito).
  4. Combinações (origem de credenciais + canal de exfiltração) somam pontos extra.
"""
import base64
import re
import time
from dataclasses import dataclass, field

BLOCK_THRESHOLD = 60   # >= bloqueia
WARN_THRESHOLD = 25    # >= suspeito (avisa, mas não bloqueia por si só)
MAX_SCAN_CHARS = 6_000_000

# limites de segurança (para ficheiros enormes / ofuscadores pesados)
TIME_BUDGET = 12.0         # segundos máximos gastos a decodificar
MAX_DEPTH = 3              # camadas de decodificação
MAX_BLOBS = 600            # blobs por texto
MAX_BRUTE = 100            # quantos blobs levam brute-force de XOR/soma
BRUTE_MAX_LEN = 4096       # tamanho máximo de um blob para brute-force
MAX_EXTRA_CHARS = 3_000_000

HIDDEN_BONUS = 15          # pontos extra se algo importante só aparece depois de decodificar
COMBO_BONUS = 25           # origem de credenciais + canal de exfiltração

# ---------------------------------------------------------------- rótulos
L_TOKEN = "Discord token pattern"
L_TOKEN_WEAK = "Possible Discord token (unverified)"
L_STORAGE = "Discord token storage (leveldb / Local Storage)"
L_ENC = "Encrypted token marker (dQw4w9WgXcQ:)"
L_ME = "Discord API account lookup (/users/@me)"
L_COOKIE_VAL = "Roblox cookie value"
L_COOKIE = "Roblox cookie (.ROBLOSECURITY)"
L_BROWSER = "Browser credential paths"
L_WEBHOOK = "Discord webhook (data exfiltration channel)"
L_TGTOKEN = "Telegram bot token"
L_TG = "Telegram bot API (exfiltration)"
L_EXFIL = "Exfiltration / logger endpoint"
L_GRABNAME = "Grabber / stealer naming"
L_ROBLOX_API = "Roblox account API (cookie use)"
L_IP = "IP lookup service"
L_APPDATA = "AppData access"
L_SHELL = "Shell / process execution"
L_HTTP = "HTTP send call"
L_AUTH = "Authorization header"
L_HIDDEN = "Hidden strings (decoded from string.char / base64 / hex / xor)"
L_COMBO = "Credential source + exfiltration channel"

# ---------------------------------------------------------------- regex base
_TOKEN = r'(?<![\w-])(?:[\w-]{23,28}\.[\w-]{6}\.[\w-]{25,110}|mfa\.[\w-]{80,95})(?![\w-])'
TOKEN_RE = re.compile(_TOKEN)

WEBHOOK_RE = re.compile(
    r'(https?://(?:[\w-]+\.)*discord(?:app)?\.com/api/(?:v\d+/)?webhooks/)(\d{15,25})/([\w-]{20,})',
    re.IGNORECASE,
)
# versão "solta": apanha também URLs incompletos, proxies de webhook e placeholders
WEBHOOK_LOOSE_RE = re.compile(
    r'(?i)api/(?:v\d+/)?webhooks/\d{3,}|webhook\.lewisakura\.moe|(?:webhooks?|hooks?)\.hyra\.io'
)

COOKIE_VALUE_RE = re.compile(
    r'(_\|WARNING:-DO-NOT-SHARE-THIS\.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items\.\|_)'
    r'([A-Za-z0-9]{50,})'
)
TG_TOKEN_RE = re.compile(r'(?<![\w:])\d{8,10}:AA[\w-]{33}(?![\w-])')

# (peso, rótulo, regex)  -- o token do Discord é tratado à parte (validação extra)
RULES = [
    (60, L_COOKIE_VAL, COOKIE_VALUE_RE),
    (50, L_STORAGE,
     re.compile(r'(?i)discord(?:canary|ptb|development)?[\\/ ]+(?:Local Storage|leveldb)|Local Storage[\\/]+leveldb')),
    (45, L_ENC, re.compile(r'dQw4w9WgXcQ:')),
    (40, L_TGTOKEN, TG_TOKEN_RE),
    (35, L_ME, re.compile(r'(?i)discord(?:app)?\.com/api/(?:v\d+/)?users/@me')),
    (35, L_TG, re.compile(r'(?i)api\.telegram\.org/bot\d{6,}')),
    (25, L_COOKIE, re.compile(r'(?i)\.ROBLOSECURITY|_\|WARNING:-DO-NOT-SHARE-THIS')),
    (25, L_ROBLOX_API,
     re.compile(r'(?i)roblox\.com/(?:v\d+/)?(?:mobileapi/userinfo|my/settings(?:\.json)?|users/authenticated|'
                r'authenticated|email|phone|birthdate|account/(?:info|settings))\b')),
    (20, L_BROWSER,
     re.compile(r'(?i:User Data[\\/]+Default|BraveSoftware|Opera Software|Google[\\/]+Chrome[\\/]+User|'
                r'Microsoft[\\/]+Edge[\\/]+User Data|Yandex[\\/]+YandexBrowser|Vivaldi|os_crypt|encrypted_key|'
                r'logins\.json|key4\.db|cookies\.sqlite)|(?-i:Login Data|Web Data|Local State)')),
    (20, L_WEBHOOK, WEBHOOK_LOOSE_RE),
    (20, L_EXFIL,
     re.compile(r'(?i)\b(?:webhook\.site|requestbin\.(?:com|net)|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|'
                r'grabify\.link|iplogger\.(?:org|com|ru)|2no\.co|yip\.su|canarytokens\.(?:com|org)|beeceptor\.com|'
                r'interact\.sh|oast\.(?:fun|me|live|online|pro|site)|burpcollaborator\.net|requestcatcher\.com|'
                r'hookbin\.com|mockbin\.org|postb\.in|transfer\.sh|api\.gofile\.io|store\d*\.gofile\.io|'
                r'pastebin\.com/api|hastebin\.com/documents)')),
    (20, L_GRABNAME,
     re.compile(r'(?i)token_?grab|cookie_?(?:grab|steal|log)|grab_?(?:token|cookie|ip)|'
                r'(?:token|cookie|password|discord)_?stealer|ip_?(?:grab|log)ger')),
    (15, L_IP,
     re.compile(r'(?i)\b(?:api\.ipify\.org|ipify\.org|ip-api\.com|ipinfo\.io|ipapi\.co|ipwho\.is|ipwhois\.app|'
                r'geoplugin\.net|icanhazip\.com|checkip\.amazonaws\.com|ifconfig\.me|ident\.me|myexternalip\.com|'
                r'api\.myip\.com|ipecho\.net|httpbin\.org/ip)')),
    (15, L_APPDATA,
     re.compile(r'(?i)%APPDATA%|%LOCALAPPDATA%|getenv\(\s*["\']?(?:APPDATA|LOCALAPPDATA)|'
                r'os\.environ\[["\']?(?:APPDATA|LOCALAPPDATA)')),
    (15, L_SHELL,
     re.compile(r'(?i)\b(?:os\.execute|io\.popen|child_process|subprocess|powershell(?:\.exe)?|cmd\.exe|WScript\.Shell)\b')),
    (10, L_HTTP,
     re.compile(r'(?i)\b(?:syn|http|fluxus|krnl)\.request\b|\bhttp_request\b|\bPostAsync\b|\bRequestAsync\b|'
                r'\bHttpPost(?:Async)?\b')),
    (10, L_AUTH, re.compile(r'(?i)["\']Authorization["\']\s*[:=,\]]')),
]

# origem de credenciais  /  canais de exfiltração (para o bónus de combinação)
SOURCES = {L_TOKEN, L_STORAGE, L_ENC, L_ME, L_COOKIE_VAL, L_COOKIE, L_BROWSER, L_ROBLOX_API}
SINKS = {L_WEBHOOK, L_TG, L_EXFIL}
# regras que fazem sentido procurar em texto invertido (string.reverse)
REVERSIBLE = {L_STORAGE, L_ENC, L_ME, L_COOKIE, L_WEBHOOK, L_TG, L_EXFIL, L_BROWSER, L_COOKIE_VAL}


# ---------------------------------------------------------------- dados
@dataclass
class Finding:
    label: str
    weight: int
    sample: str = ""
    hidden: bool = False


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


# ---------------------------------------------------------------- tokens
def _b64_digits(part: str) -> bool:
    """A 1ª parte de um token do Discord é o ID do utilizador em base64 (17-20 dígitos)."""
    try:
        raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except Exception:
        return False
    return raw.isdigit() and 17 <= len(raw) <= 20


def _is_strong_token(tok: str) -> bool:
    if tok.startswith("mfa."):
        return True
    return _b64_digits(tok.split(".", 1)[0])


def _find_token(s: str):
    """Devolve (match_forte, match_fraco)."""
    weak = None
    for m in TOKEN_RE.finditer(s):
        if _is_strong_token(m.group(0)):
            return m, weak
        if weak is None:
            weak = m
    return None, weak


def mask_token(tok: str, ch: str = "•") -> str:
    return tok[:6] + ch * 8


def mask_webhook(url: str) -> str:
    m = WEBHOOK_RE.search(url)
    if not m:
        return url[:40]
    return f"{m.group(1)}{m.group(2)}/{m.group(3)[:4]}••••"


def _sample(label: str, raw: str) -> str:
    if label in (L_TOKEN, L_TOKEN_WEAK, L_TGTOKEN):
        return mask_token(raw)
    if label == L_WEBHOOK:
        return mask_webhook(raw)
    if label == L_COOKIE_VAL:
        return raw[:24] + "••••"
    return raw[:48].replace("\n", " ")


# ---------------------------------------------------------------- normalização
_DEC_ESC = re.compile(r'\\(\d{1,3})')
_HEX_ESC = re.compile(r'\\x([0-9a-fA-F]{2})')
_UNI_ESC = re.compile(r'\\u\{([0-9a-fA-F]{1,6})\}')
_PCT = re.compile(r'(?:%[0-9a-fA-F]{2}){6,}')
_INVISIBLE = re.compile('[\u200b-\u200f\u2060\ufeff\u00ad]')
_CONCAT = re.compile(r'''["']\s*\.\.\s*["']''')
_COMMAS = re.compile(r'''["']\s*,\s*["']''')
_CONCAT_FN = re.compile(r'(?i)table\s*\.\s*concat|\bconcat\b')


def _unescape(text: str) -> str:
    """Decodifica \\104\\116..., \\x68..., \\u{68} e %68%74... (muito usado por ofuscadores)."""
    if text.count("\\") > 3_000_000:
        return text
    text = _DEC_ESC.sub(lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), text)
    text = _HEX_ESC.sub(lambda m: chr(int(m.group(1), 16)), text)
    text = _UNI_ESC.sub(
        lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 0x110000 else m.group(0), text)
    text = _PCT.sub(lambda m: bytes.fromhex(m.group(0).replace("%", "")).decode("latin-1"), text)
    return text


def _fold_concat(text: str) -> str:
    """"disc".."ord.com" -> "discord.com"."""
    for _ in range(4):
        new = _CONCAT.sub("", text)
        if new == text:
            break
        text = new
    return text


def _variants(text: str):
    """Versões normalizadas do código. [0] é sempre o original; a última é a mais normalizada."""
    vs = [text]
    cur = _INVISIBLE.sub("", text)
    cur = _fold_concat(cur)
    if cur != text:
        vs.append(cur)
    if _CONCAT_FN.search(cur):                      # table.concat({"https://dis","cord.com/..."})
        joined = _COMMAS.sub("", cur)
        if joined != cur:
            vs.append(joined)
            cur = joined
    if "\\" in cur or "%" in cur:
        un = _unescape(cur)
        if un != cur:
            vs.append(un)
    return vs


# ---------------------------------------------------------------- strings escondidas
_PRINT = bytes([9, 10, 13] + list(range(32, 127)))

_DEC_LIST = re.compile(r'(?<![\w.])(?:\d{1,3}\s*,\s*){7,}\d{1,3}(?![\w.])')
_NUM = re.compile(r'\d+')
_HEX_LIST = re.compile(r'(?:0[xX][0-9a-fA-F]{1,2}\s*,\s*){7,}0[xX][0-9a-fA-F]{1,2}(?![0-9a-fA-F])')
_HEXNUM = re.compile(r'0[xX]([0-9a-fA-F]{1,2})')
_ESC_RUN = re.compile(r'(?:\\(?:\d{1,3}|x[0-9a-fA-F]{2})){8,}')
_ESC_TOK = re.compile(r'\\(?:(\d{1,3})|x([0-9a-fA-F]{2}))')
_B64 = re.compile(r'(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9+/=_-])')
_HEXBLOB = re.compile(r'(?<![0-9A-Za-z])(?:[0-9a-fA-F]{2}){12,}(?![0-9A-Za-z])')

_KEYWORDS_B = re.compile(
    rb'(?i)discord|webhook|roblosecurity|https?://|leveldb|local storage|users/@me|authorization|token')
_XOR_TABLES = [bytes(b ^ k for b in range(256)) for k in range(256)]
_ADD_TABLES = [bytes((b + k) & 255 for b in range(256)) for k in range(256)]
_CRIBS = [
    b"https://discord.com/api/webhooks/", b"https://discordapp.com/api/webhooks/",
    b"https://canary.discord.com/api/webhooks/", b"https://ptb.discord.com/api/webhooks/",
    b"https://discord.com/api/v9/users/@me", b"https://discord.com/api/v10/users/@me",
    b"https://discord.com/api/v8/users/@me", b"https://discord.com/api/users/@me",
    b"discord.com/api/webhooks/", b"https://", b"http://",
]


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return 1.0 - len(b.translate(None, _PRINT)) / len(b)


def _b64decode(s: str):
    s = s.rstrip("=")
    if len(s) % 4 == 1:
        return None
    s += "=" * (-len(s) % 4)
    try:
        if "-" in s or "_" in s:
            return base64.urlsafe_b64decode(s)
        return base64.b64decode(s)
    except Exception:
        return None


def _iter_blobs(text: str):
    """Gera (tipo, match, bytes) para cada sequência que parece dados codificados."""
    n = 0
    for m in _DEC_LIST.finditer(text):
        s = m.group(0)
        if len(s) > 4_000_000:
            continue
        vals = [int(x) for x in _NUM.findall(s)]
        if vals and max(vals) <= 255:
            yield "dec", m, bytes(vals)
            n += 1
            if n >= MAX_BLOBS:
                return
    for m in _HEX_LIST.finditer(text):
        vals = [int(x, 16) for x in _HEXNUM.findall(m.group(0))]
        yield "hex", m, bytes(vals)
        n += 1
        if n >= MAX_BLOBS:
            return
    for m in _ESC_RUN.finditer(text):
        vals = [int(d) if d else int(h, 16) for d, h in _ESC_TOK.findall(m.group(0))]
        if vals and max(vals) <= 255:
            yield "esc", m, bytes(vals)
            n += 1
            if n >= MAX_BLOBS:
                return
    for m in _B64.finditer(text):
        if len(m.group(0)) > 3_000_000:
            continue
        data = _b64decode(m.group(0))
        if data and len(data) >= 12:
            yield "b64", m, data
            n += 1
            if n >= MAX_BLOBS * 5:
                return
    for m in _HEXBLOB.finditer(text):
        try:
            data = bytes.fromhex(m.group(0))
        except ValueError:
            continue
        yield "hexblob", m, data
        n += 1
        if n >= MAX_BLOBS * 5:
            return


def _crib_decode(data: bytes, crib: bytes):
    """XOR com chave repetida (até 24 bytes) assumindo que o texto começa por `crib`."""
    n = min(len(data), len(crib))
    for L in range(1, min(n // 2, 24) + 1):
        key = bytes(data[i] ^ crib[i] for i in range(L))
        if all(data[i] ^ key[i % L] == crib[i] for i in range(L, n)):
            return bytes(b ^ key[i % L] for i, b in enumerate(data))
    return None


class _State:
    __slots__ = ("deadline", "chars", "brute", "seen", "out")

    def __init__(self, deadline: float):
        self.deadline = deadline
        self.chars = 0
        self.brute = 0
        self.seen = set()
        self.out = []


def _decode_candidates(data: bytes, allow_brute: bool, st: _State):
    """Textos possíveis a partir de bytes: direto, XOR/soma de 1 byte, XOR com chave repetida."""
    if len(data) < 8:
        return []
    out = []
    if _printable_ratio(data) >= 0.85:
        out.append(data)
        if _KEYWORDS_B.search(data):
            return out
    if allow_brute and 12 <= len(data) <= BRUTE_MAX_LEN and st.brute < MAX_BRUTE:
        st.brute += 1
        for tabs in (_XOR_TABLES, _ADD_TABLES):
            for k in range(1, 256):
                d = data.translate(tabs[k])
                if _KEYWORDS_B.search(d) and _printable_ratio(d) >= 0.9:
                    out.append(d)
                    return out
        if len(data) >= 16:
            for crib in _CRIBS:
                d = _crib_decode(data, crib)
                if d is not None and _printable_ratio(d) >= 0.9:
                    out.append(d)
                    return out
    return out


def _expand(text: str, depth: int, st: _State):
    if depth >= MAX_DEPTH:
        return
    for kind, _m, data in _iter_blobs(text):
        if time.monotonic() > st.deadline or st.chars > MAX_EXTRA_CHARS:
            return
        h = hash(data)
        if h in st.seen:
            continue
        st.seen.add(h)
        for d in _decode_candidates(data, kind in ("dec", "hex", "esc"), st):
            txt = d.decode("latin-1")
            st.chars += len(txt)
            st.out.append(txt)
            _expand(txt, depth + 1, st)


def _hidden_texts(variants):
    st = _State(time.monotonic() + TIME_BUDGET)
    for v in variants:
        _expand(v, 0, st)
        if time.monotonic() > st.deadline or st.chars > MAX_EXTRA_CHARS:
            break
    return st.out


# ---------------------------------------------------------------- redação
def _redact_encoded(text: str) -> str:
    """Se um token/webhook estiver escondido em string.char / base64 / hex, mascara-o lá dentro."""
    reps = []
    for kind, m, data in _iter_blobs(text):
        if len(data) < 8 or _printable_ratio(data) < 0.85:
            continue
        dec = data.decode("latin-1")
        red = redact_text(dec, ch="*", encoded=False)
        if red == dec:
            continue
        new = red.encode("latin-1", "replace")
        if kind == "dec":
            s = ",".join(str(b) for b in new)
        elif kind == "hex":
            s = ",".join("0x%02x" % b for b in new)
        elif kind == "esc":
            s = "".join("\\%03d" % b for b in new)
        elif kind == "b64":
            s = base64.b64encode(new).decode()
        elif kind == "hexblob":
            s = new.hex()
        else:
            continue
        reps.append((m.start(), m.end(), s))
    if not reps:
        return text
    reps.sort()
    out, pos = [], 0
    for a, b, s in reps:
        if a < pos:
            continue
        out.append(text[pos:a])
        out.append(s)
        pos = b
    out.append(text[pos:])
    return "".join(out)


def redact_text(text: str, ch: str = "•", encoded: bool = True) -> str:
    """Esconde tokens do Discord, a parte secreta de webhooks, cookies Roblox e tokens do Telegram
    (também quando estão escondidos em string.char / base64 / hex)."""
    text = TOKEN_RE.sub(
        lambda m: mask_token(m.group(0), ch) if _is_strong_token(m.group(0)) else m.group(0), text)
    text = WEBHOOK_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}/{m.group(3)[:4]}{ch * 4}", text)
    text = COOKIE_VALUE_RE.sub(lambda m: m.group(1) + ch * 8, text)
    text = TG_TOKEN_RE.sub(lambda m: mask_token(m.group(0), ch), text)
    if encoded:
        text = _redact_encoded(text)
    return text


def redact_bytes(data: bytes) -> bytes:
    return redact_text(data.decode("utf-8", "replace")).encode("utf-8")


# ---------------------------------------------------------------- scan
def scan(text) -> ScanResult:
    if isinstance(text, bytes):
        text = text.decode("utf-8", "ignore")
    text = text[:MAX_SCAN_CHARS]

    variants = _variants(text)
    extra_parts = variants[1:]
    extra_parts.extend(_hidden_texts(variants))
    extra = "\n".join(extra_parts)

    rev = None
    if re.search(r'(?i)reverse', text):
        rev = variants[-1][::-1]

    findings = {}

    def add(label, weight, raw, hidden=False, tag="decoded"):
        if label in findings:
            return
        shown = f"{label} ({tag})" if hidden else label
        findings[label] = Finding(shown, weight, _sample(label, raw), hidden)

    # token do Discord (com validação do ID em base64)
    strong, weak = _find_token(text)
    if strong:
        add(L_TOKEN, 60, strong.group(0))
    else:
        s2, w2 = _find_token(extra) if extra else (None, None)
        if s2:
            add(L_TOKEN, 60, s2.group(0), True)
        elif weak or w2:
            add(L_TOKEN_WEAK, 20, (weak or w2).group(0), hidden=weak is None)

    for weight, label, rx in RULES:
        m = rx.search(text)
        if m:
            add(label, weight, m.group(0))
            continue
        if extra:
            m = rx.search(extra)
            if m:
                add(label, weight, m.group(0), True)
                continue
        if rev is not None and label in REVERSIBLE:
            m = rx.search(rev)
            if m:
                add(label, weight, m.group(0), True, "reversed")

    keys = set(findings)

    # algo importante que só aparece depois de decodificar => esconder é, por si só, suspeito
    if any(f.hidden and f.weight >= 20 for f in findings.values()):
        findings[L_HIDDEN] = Finding(L_HIDDEN, HIDDEN_BONUS, "found only after decoding", True)

    # origem de credenciais + canal de exfiltração
    if keys & SOURCES and keys & SINKS:
        findings[L_COMBO] = Finding(L_COMBO, COMBO_BONUS, "")

    result = ScanResult()
    result.findings = sorted(findings.values(), key=lambda f: -f.weight)
    result.score = min(100, sum(f.weight for f in result.findings))
    return result
