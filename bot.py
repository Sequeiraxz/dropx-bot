import os
import io
import asyncio
import tempfile
import re
import json
import math
import time
import traceback
import aiohttp
import discord
from collections import Counter
from discord.ext import commands
from aiohttp import web

TOKEN = os.environ.get("DISCORD_TOKEN")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEOBF_DIR = os.environ.get("DEOBF_DIR", "./Prometheus-Deobfuscator-main")
MOONSEC_V2_DIR = os.path.join(BASE_DIR, "moonsec-v2-deobfuscator")
MOONVEIL_DIR = os.path.join(BASE_DIR, "moonveil-deobf")
LUAOBFUSCATOR_DIR = os.path.join(BASE_DIR, "luaobfuscator-deobf", "luaobfuscator")
ENVLOG_PATH = os.path.join(BASE_DIR, "envlog.luau")
ENVLOG2_PATH = os.environ.get("ENVLOG2_PATH", os.path.join(BASE_DIR, "envlog2.luau"))
NODE = os.environ.get("NODE", "node")
LUNE = os.environ.get("LUNE", "/usr/local/bin/lune")
DEOBF_TIMEOUT = int(os.environ.get("DEOBF_TIMEOUT", "180"))
CONFIG_FILE = os.environ.get("CONFIG_FILE", "config.json")

HEADER = "Deobfuscate By DropX :)\n\n"
BOT_NAME = "DropX"
MAX_FILE = 5 * 1024 * 1024

WEAREDEVS_EMOJI_ID = 1565837351769481216
MOONSEC_EMOJI_ID = 1566041038852718692
MOONVEIL_EMOJI_ID = 1566062539962323085
LUAOBF_EMOJI_ID = 1566411737727770714

WEAREDEVS_ICON = "https://www.google.com/s2/favicons?domain=wearedevs.net&sz=128"
MOONSEC_ICON = f"https://cdn.discordapp.com/emojis/{MOONSEC_EMOJI_ID}.png"
MOONVEIL_ICON = f"https://cdn.discordapp.com/emojis/{MOONVEIL_EMOJI_ID}.png"
LUAOBF_ICON = f"https://cdn.discordapp.com/emojis/{LUAOBF_EMOJI_ID}.png"

# ---------- ESTILO ----------
C_BRAND = 0x2ECC71
C_OK = 0x2ECC71
C_WORK = 0xF1C40F
C_ERR = 0xE74C3C
C_DARK = 0x2B2D31

OBF_STYLE = {
    "Prometheus": (0xE67E22, WEAREDEVS_ICON),
    "MoonSec V2": (0x3498DB, MOONSEC_ICON),
    "MoonVeil": (0x9B59B6, MOONVEIL_ICON),
    "LuaObfuscator VM": (0xF1C40F, LUAOBF_ICON),
    "Custom / Unknown": (0x95A5A6, None),
}


def bar(score10: int) -> str:
    score10 = max(0, min(10, score10))
    return "▰" * score10 + "▱" * (10 - score10)


def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB"):
        if n < 1024 or unit == "MB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} B"


def fmt_uptime(sec: int) -> str:
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def make_embed(title, description=None, color=C_BRAND, footer=True):
    e = discord.Embed(title=title, description=description, color=color)
    if footer:
        e.set_footer(text=f"Made by {BOT_NAME}")
    return e


def working_embed(tool_label: str):
    return make_embed("⏳ Working...", f"Running **{tool_label}**\nThis can take a few seconds.", C_WORK)


def error_embed(tool_label: str, err: str):
    e = make_embed("❌ Failed", f"**{tool_label}** could not finish.", C_ERR)
    e.add_field(name="Details", value=f"```\n{(err or 'no details')[-900:]}\n```", inline=False)
    return e


def result_embed(tool_label: str, size: int, elapsed: float):
    e = make_embed("✅ Done", None, C_OK)
    e.add_field(name="Tool", value=tool_label, inline=True)
    e.add_field(name="Size", value=fmt_bytes(size), inline=True)
    e.add_field(name="Time", value=f"{elapsed:.1f}s", inline=True)
    return e


# ---------- CONFIG ----------
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {"channel_id": None}


def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f)


config = load_config()

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=".", intents=intents)
bot.remove_command("help")

_moonsec_lock = asyncio.Lock()
_moonveil_lock = asyncio.Lock()

# ---------- DETECTOR ----------
SIGNATURES = {
    "Prometheus": [
        (20, re.compile(r'return\s*\(function\s*\(\.\.\.\)\s*local\s+\w\s*=\s*\{')),
        (45, re.compile(r"=\{\s*(?:'[A-Za-z0-9]+'\s*,\s*){4,}'[A-Za-z0-9]+'\s*\}")),
        (20, re.compile(r'\b\d{4,7}-\(-?\d{4,7}\)')),
        (15, re.compile(r'math\.floor')),
        (10, re.compile(r'string\.char.*table\.concat.*string\.sub', re.DOTALL)),
        (15, re.compile(r'for\s+\w+,\w+\s+in\s+ipairs\s*\(')),
        (10, re.compile(r'getfenv\s+and\s+getfenv\(\)\s+or\s+_ENV')),
        (20, re.compile(r'local\s+function\s+\w\s*\(\w\)\s*return\s+\w\[\w\+')),
        (12, re.compile(r'bit32\.rrotate')),
        (8, re.compile(r'bit32\.rshift')),
        (35, re.compile(r"^return\s*\(\s*function\s*\(\s*\.\.\.\s*\)\s*local\s+\w\s*=\s*\{\s*'", re.MULTILINE)),
    ],
    "MoonSec V2": [
        (25, re.compile(r'Protected_by_MoonSecV2')),
        (50, re.compile(r'[\u3480-\u34c0]{5,}')),
        (25, re.compile(r'_msec\s*=')),
        (20, re.compile(r'#\[\[[^\]]{3,}\]\]')),
        (15, re.compile(r'\(0x[0-9a-f]+/\d+\)')),
        (10, re.compile(r'discord\.gg/gQEH')),
    ],
    "MoonVeil": [
        (50, re.compile(r'--\s*This script was generated using (?:the )?MoonVeil')),
        (40, re.compile(r'moonveil\.cc')),
        (35, re.compile(r'local\s+\w+,\w+,\w+,\w+=getmetatable,bit32\.bxor,pairs,type')),
        (25, re.compile(r'bit32\s*\.\s*lshift\s*,\s*bit32\s*\.\s*rshift\s*,\s*bit32\s*\.\s*band')),
    ],
    "LuaObfuscator VM": [
        (50, re.compile(r'local\s+v0\s*=\s*tonumber\s*;\s*local\s+v1\s*=\s*string\.byte')),
        (35, re.compile(r'local\s+function\s+v15\s*\(v16,v17')),
        (50, re.compile(r'return\s+v15\s*\(\s*"LOL!')),
        (15, re.compile(r'getfenv\s+or\s+function\s*\(\s*\)\s*return\s+_ENV')),
    ],
}
_DEFINITELY_OBF = [
    re.compile(r'Protected_by_MoonSecV2'),
    re.compile(r'This script was generated using (?:the )?MoonVeil'),
    re.compile(r'return\s+v15\s*\(\s*"LOL!'),
    re.compile(r'[\u3480-\u34c0]{5,}'),
]
_WEAREDEVS_SIGNALS = [
    re.compile(r'wearedevs\.net/obfuscator'),
    re.compile(r'\[\[\s*v\d+\.\d+\.\d+\s+https?://'),
]


def calc_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def stat_features(code: str) -> dict:
    lines = code.splitlines()
    total_chars = len(code)
    if total_chars == 0:
        return {}
    num_esc = len(re.findall(r'\\[0-9]{2,3}', code))
    return {
        "entropy": calc_entropy(code),
        "numeric_escape_density": num_esc / max(total_chars / 1000, 1),
        "avg_line_length": (sum(len(l) for l in lines) / len(lines)) if lines else 0,
    }


def _any_match(patterns, code):
    for pat in patterns:
        try:
            if pat.search(code):
                return True
        except Exception:
            pass
    return False


def is_wearedevs(code: str) -> bool:
    return _any_match(_WEAREDEVS_SIGNALS, code)


def is_definitely_obfuscated(code: str) -> bool:
    return _any_match(_DEFINITELY_OBF, code)


def detect(code):
    definitely = is_definitely_obfuscated(code)
    wad = is_wearedevs(code)
    raw_scores = {}
    for obf_name, patterns in SIGNATURES.items():
        score = 0.0
        for weight, pattern in patterns:
            try:
                if pattern.search(code):
                    score += weight
            except Exception:
                pass
        if obf_name == "Prometheus" and definitely:
            score += 10
        if obf_name == "Prometheus" and wad:
            score -= 40
        raw_scores[obf_name] = max(score, 0.0)
    if not raw_scores:
        return [("Custom / Unknown", 0.0)]
    top = sorted(raw_scores.items(), key=lambda x: x[1], reverse=True)
    top_name, top_score = top[0]
    if top_score < 20:
        return [("Custom / Unknown", 0.0)]
    total = sum(raw_scores.values()) or 1
    out = []
    for name, sc in raw_scores.items():
        if name == top_name:
            conf = min(99.9, (sc / total) * 55 + min(sc / 120, 1) * 45)
        else:
            conf = 0.0 if sc <= 0 else min(99.9, (sc / top_score) * 20)
        out.append((name, round(conf, 1)))
    out.sort(key=lambda x: x[1], reverse=True)
    return out


def score_1_to_10(pct: float) -> int:
    return max(1, min(10, int(round(pct / 10.0))))


# ---------- WEB ----------
async def handle_ping(request):
    return web.Response(text="DropX Bot Online")


async def start_web_server():
    app = web.Application()
    app.router.add_get("/", handle_ping)
    runner = web.AppRunner(app)
    await runner.setup()
    port = int(os.environ.get("PORT", 8080))
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    print(f"Web server running on port {port}", flush=True)


# ---------- RUNNERS ----------
async def run_deobf(source: bytes):
    with tempfile.TemporaryDirectory() as tmp:
        in_path = os.path.join(tmp, "input.lua")
        out_path = os.path.join(tmp, "out.lua")
        with open(in_path, "wb") as f:
            f.write(source)
        try:
            proc = await asyncio.create_subprocess_exec(
                NODE, "bin/pdeobf.js", in_path, "-o", out_path,
                cwd=DEOBF_DIR,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=DEOBF_TIMEOUT)
        except asyncio.TimeoutError:
            return None, f"timeout ({DEOBF_TIMEOUT}s)"
        except FileNotFoundError:
            return None, "Node.js not found"
        if proc.returncode != 0 or not os.path.exists(out_path):
            return None, stderr.decode("utf-8", "replace")[-1200:]
        with open(out_path, "rb") as f:
            return (HEADER.encode("utf-8") + f.read()), ""


async def run_moonsec_v2(source: bytes):
    if not os.path.isdir(MOONSEC_V2_DIR):
        return None, "moonsec-v2-deobfuscator folder missing"
    async with _moonsec_lock:
        with tempfile.TemporaryDirectory() as tmp:
            in_path = os.path.join(tmp, "input.lua")
            with open(in_path, "wb") as f:
                f.write(source)
            try:
                proc = await asyncio.create_subprocess_exec(
                    "python", "main.py", in_path,
                    cwd=MOONSEC_V2_DIR,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            except asyncio.TimeoutError:
                return None, "timeout (300s)"
            except FileNotFoundError:
                return None, "Python/main.py not found"
            out_path = os.path.join(MOONSEC_V2_DIR, "output.lua")
            if proc.returncode != 0 or not os.path.exists(out_path):
                msg = (stdout + stderr).decode("utf-8", "replace").strip()
                return None, msg[-1200:] or "failed with no output"
            with open(out_path, "rb") as f:
                result = f.read()
            try:
                os.remove(out_path)
            except Exception:
                pass
            return result, ""


async def run_moonveil(source: bytes):
    if not os.path.isdir(MOONVEIL_DIR):
        return None, "moonveil-deobf folder missing"
    async with _moonveil_lock:
        with tempfile.TemporaryDirectory() as tmp:
            in_path = os.path.join(tmp, "input.lua")
            out_path = os.path.join(tmp, "recovered.lua")
            with open(in_path, "wb") as f:
                f.write(source)
            try:
                proc = await asyncio.create_subprocess_exec(
                    "python", "-m", "moonveil", "deobfuscate", in_path, "-o", out_path,
                    cwd=MOONVEIL_DIR,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
            except asyncio.TimeoutError:
                return None, "timeout (180s)"
            except FileNotFoundError:
                return None, "Python/moonveil not found"
            if proc.returncode != 0 or not os.path.exists(out_path):
                msg = (stdout + stderr).decode("utf-8", "replace").strip()
                return None, msg[-1200:] or f"exit code {proc.returncode}"
            with open(out_path, "rb") as f:
                return f.read(), ""


async def run_luaobfuscator(source: bytes):
    if not os.path.isdir(LUAOBFUSCATOR_DIR):
        return None, "luaobfuscator folder missing"
    async with _moonveil_lock:
        with tempfile.TemporaryDirectory() as tmp:
            in_path = os.path.join(tmp, "input.lua")
            with open(in_path, "wb") as f:
                f.write(source)
            try:
                proc = await asyncio.create_subprocess_exec(
                    "node", "src/cli.js", in_path, "--stdout",
                    cwd=LUAOBFUSCATOR_DIR,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
            except asyncio.TimeoutError:
                return None, "timeout (180s)"
            except FileNotFoundError:
                return None, "Node.js not found"
            if proc.returncode != 0:
                return None, stderr.decode("utf-8", "replace").strip()[-1200:] or f"exit code {proc.returncode}"
            return stdout, ""


def envlog_config_lua() -> str:
    """Config injetada no env logger através de variáveis de ambiente."""
    parts = []
    if os.environ.get("ENVLOG_TRACE_READS") == "1":
        parts.append("TRACE_GLOBAL_READS = true")
    if os.environ.get("ENVLOG_AUTO_STUB") == "1":
        parts.append("AUTO_STUB_UPPER = true")
    return "{" + ", ".join(parts) + "}"


async def _run_lune_logger(path: str, source: bytes, timeout: float):
    name = os.path.basename(path)
    if not os.path.exists(path):
        return None, f"{name} not found in project root"
    try:
        with open(path, "r", encoding="utf-8") as f:
            envlog_code = f.read()
    except Exception as e:
        return None, f"failed to read {name}: {e}"

    script_text = source.decode("utf-8", "ignore")
    eq = "=" * 5
    while (']' + eq + ']') in script_text:
        eq += "="
    safe_source = f"[{eq}[{script_text}]{eq}]"

    prelude = (
        f"local __SOURCE = {safe_source}\n"
        f"local __ENVLOG_CONFIG = {envlog_config_lua()}\n"
        f"local __CONFIG = {{}}\n"
        f"local __ROBLOX = {{ enums = '', classes = '' }}\n"
        f"local __UNICODE = {{ decomp = '', ccc = '', comp = '' }}\n"
        f"local __P2D = {{}}\n"
        f"local __CHUNKS = {{}}\n"
    )
    runner = prelude + envlog_code

    with tempfile.TemporaryDirectory() as tmp:
        runner_path = os.path.join(tmp, "envlog_runner.luau")
        with open(runner_path, "w", encoding="utf-8") as f:
            f.write(runner)
        try:
            proc = await asyncio.create_subprocess_exec(
                LUNE, "run", runner_path,
                cwd=BASE_DIR,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            return None, f"timeout ({int(timeout)}s)"
        except FileNotFoundError:
            return None, f"lune not found at {LUNE}"

        if proc.returncode != 0:
            return None, f"lune exit {proc.returncode}: {stderr.decode('utf-8', 'replace')[-1200:]}"
        out = stdout.decode("utf-8", "replace")
        if not out.strip():
            return None, f"{name} produced no output"
        return out.encode("utf-8"), ""


async def run_envlog(source: bytes):
    return await _run_lune_logger(ENVLOG_PATH, source, 300)


async def run_envlog2(source: bytes):
    return await _run_lune_logger(ENVLOG2_PATH, source, float(os.environ.get("ENVLOG2_TIMEOUT", "120")))


async def fetch_url(url: str):
    if not re.match(r"^https?://", url):
        return None, "Invalid URL"
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status != 200:
                    return None, f"HTTP {r.status}"
                return await r.read(), ""
    except Exception as e:
        return None, str(e)


# ---------- FERRAMENTAS (botões gerados a partir desta lista) ----------
TOOLS = [
    {"key": "Prometheus", "label": "Prometheus", "run": run_deobf, "file": "deobfuscated.txt",
     "emoji": discord.PartialEmoji(name="wearedevs", id=WEAREDEVS_EMOJI_ID), "row": 0,
     "match": ("Prometheus", "WeAreDevs")},
    {"key": "MoonSec V2", "label": "MoonSec V2", "run": run_moonsec_v2, "file": "deobfuscated.lua",
     "emoji": discord.PartialEmoji(name="moonsec", id=MOONSEC_EMOJI_ID), "row": 0,
     "match": ("MoonSec V2",)},
    {"key": "MoonVeil", "label": "MoonVeil", "run": run_moonveil, "file": "deobfuscated.lua",
     "emoji": discord.PartialEmoji(name="moonveil", id=MOONVEIL_EMOJI_ID), "row": 0,
     "match": ("MoonVeil",)},
    {"key": "LuaObfuscator", "label": "LuaObfuscator", "run": run_luaobfuscator, "file": "deobfuscated.lua",
     "emoji": discord.PartialEmoji(name="luaobf", id=LUAOBF_EMOJI_ID), "row": 0,
     "match": ("LuaObfuscator VM", "LuaObfuscator")},
    {"key": "EnvLog", "label": "Env Logger", "run": run_envlog, "file": "envlog_output.lua",
     "emoji": "📜", "row": 1, "match": ()},
    {"key": "EnvLog2", "label": "Env Logger 2", "run": run_envlog2, "file": "envlog2_output.lua",
     "emoji": "🧪", "row": 1, "match": ()},
]


class ToolButton(discord.ui.Button):
    def __init__(self, tool: dict, recommended: bool = False):
        super().__init__(
            label=tool["label"],
            style=discord.ButtonStyle.success if recommended else discord.ButtonStyle.secondary,
            emoji=tool["emoji"],
            row=tool["row"],
        )
        self.tool = tool

    async def callback(self, interaction: discord.Interaction):
        try:
            src = getattr(self.view, "source", None)
            if not src:
                return await interaction.response.send_message("Script not found.", ephemeral=True)
            self.view.stop()
            await interaction.response.edit_message(embed=working_embed(self.tool["label"]), view=None)
            started = time.time()
            res, err = await self.tool["run"](src)
            elapsed = time.time() - started
            if not res:
                return await interaction.edit_original_response(embed=error_embed(self.tool["label"], err))
            file = discord.File(fp=io.BytesIO(res), filename=self.tool["file"])
            await interaction.edit_original_response(
                embed=result_embed(self.tool["label"], len(res), elapsed),
                attachments=[file],
            )
        except Exception as e:
            traceback.print_exc()
            try:
                await interaction.edit_original_response(embed=error_embed(self.tool["label"], repr(e)))
            except Exception:
                pass


class DeobfView(discord.ui.View):
    def __init__(self, source: bytes, owner_id: int, detected: str = ""):
        super().__init__(timeout=600)
        self.source = source
        self.owner_id = owner_id
        for tool in TOOLS:
            self.add_item(ToolButton(tool, recommended=detected in tool["match"]))

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message("Only the person who ran the command can use these buttons.", ephemeral=True)
            return False
        return True


# ---------- HELP (com menu dropdown) ----------
CATEGORIES = {
    "Utilities": {"emoji": "⚙️", "desc": "Setup and information"},
    "Tools": {"emoji": "🌙", "desc": "Deobfuscation and analysis"},
}

COMMANDS = {
    "alojar": ("Utilities", ".alojar", "Host the bot in the current channel. Administrators only."),
    "stats": ("Utilities", ".stats", "Show uptime and latency."),
    "help": ("Utilities", ".help [command]", "Show this menu, or details about one command."),
    "deobf": ("Tools", ".deobf <url | attachment>",
              "Detects the obfuscator and shows the matching deobfuscation buttons plus the env loggers."),
    "detector": ("Tools", ".detector <url | attachment>", "Only detects which obfuscator was used."),
    "l": ("Tools", ".l <url | attachment>", "Runs the env logger."),
    "l2": ("Tools", ".l2 <url | attachment>", "Runs env logger 2 (improved)."),
}


def category_commands(cat: str):
    return [name for name, (c, _, _) in COMMANDS.items() if c == cat]


def help_embed(cat: str, user: discord.abc.User = None):
    info = CATEGORIES[cat]
    e = discord.Embed(
        title="Helper",
        description="Use `.help <command>` for details about a specific command.",
        color=C_BRAND,
    )
    chips = " · ".join(f"`{n}`" for n in category_commands(cat))
    e.add_field(name=f"{info['emoji']} {cat}", value=chips, inline=False)
    footer = f"Made by {BOT_NAME}"
    if user is not None:
        footer += f" · requested by {user.display_name}"
    e.set_footer(text=footer)
    return e


class HelpSelect(discord.ui.Select):
    def __init__(self, current: str):
        options = [
            discord.SelectOption(
                label=cat,
                description=f"{len(category_commands(cat))} command(s)",
                emoji=info["emoji"],
                default=(cat == current),
            )
            for cat, info in CATEGORIES.items()
        ]
        super().__init__(placeholder="Choose a category", options=options, min_values=1, max_values=1)

    async def callback(self, interaction: discord.Interaction):
        cat = self.values[0]
        view = HelpView(self.view.owner_id, cat, interaction.user)
        await interaction.response.edit_message(embed=help_embed(cat, interaction.user), view=view)


class HelpView(discord.ui.View):
    def __init__(self, owner_id: int, current: str = "Tools", user=None):
        super().__init__(timeout=180)
        self.owner_id = owner_id
        self.add_item(HelpSelect(current))

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message("Run `.help` yourself to use this menu.", ephemeral=True)
            return False
        return True


# ---------- UTILIDADES ----------
async def get_source(ctx: commands.Context, url: str = None):
    if ctx.message.attachments:
        att = ctx.message.attachments[0]
        if not att.filename.endswith((".txt", ".lua", ".luau")):
            return None, "Attachment must be .txt/.lua/.luau"
        if att.size > MAX_FILE:
            return None, "File > 5 MiB."
        return await att.read(), ""
    elif url:
        source, err = await fetch_url(url.strip())
        if source is None:
            return None, f"Could not fetch URL: {err}"
        if len(source) > MAX_FILE:
            return None, "File > 5 MiB."
        return source, ""
    return None, "Usage: attach a file or send a URL."


async def channel_ok(ctx: commands.Context, quiet=False) -> bool:
    if config["channel_id"] is None:
        await ctx.reply(embed=make_embed("Bot not hosted", "Use `.alojar` in the channel you want to use.", C_ERR))
        return False
    if ctx.channel.id != config["channel_id"] and not quiet:
        await ctx.reply(embed=make_embed("Wrong channel", f"Use <#{config['channel_id']}>.", C_ERR), delete_after=6)
        return False
    return True


# ---------- COMANDOS ----------
@bot.command(name="alojar")
@commands.has_permissions(administrator=True)
async def alojar(ctx: commands.Context):
    config["channel_id"] = ctx.channel.id
    save_config(config)
    await ctx.reply(embed=make_embed("✅ Hosted", f"The bot is now hosted in {ctx.channel.mention}.", C_OK), delete_after=10)


@bot.command(name="deobf")
async def deobf(ctx: commands.Context, *, url: str = None):
    if not await channel_ok(ctx):
        return
    source, err = await get_source(ctx, url)
    if source is None:
        return await ctx.reply(embed=make_embed("Could not read the script", err, C_ERR), delete_after=8)

    results = detect(source.decode("utf-8", "ignore"))
    top_name, top_pct = results[0] if results else ("Custom / Unknown", 0.0)
    color, icon = OBF_STYLE.get(top_name, (C_BRAND, None))
    score = score_1_to_10(top_pct) if top_pct > 0 else 0

    e = discord.Embed(title="🔓 DropX Deobfuscator", color=color)
    e.add_field(name="Detected", value=f"**{top_name}**", inline=True)
    e.add_field(name="Confidence", value=f"`{bar(score)}` {score}/10", inline=True)
    e.add_field(name="Size", value=fmt_bytes(len(source)), inline=True)

    others = [f"`{n}` {score_1_to_10(p)}/10" for n, p in results[1:4] if p > 0]
    if others:
        e.add_field(name="Other matches", value=" · ".join(others), inline=False)

    if any(top_name in t["match"] for t in TOOLS):
        hint = "The green button is the recommended tool for this script."
    else:
        hint = "No obfuscator recognised. Try any deobfuscator or the Env Loggers."
    e.add_field(name="Next step", value=hint, inline=False)
    if icon:
        e.set_thumbnail(url=icon)
    e.set_footer(text=f"Made by {BOT_NAME} · requested by {ctx.author.display_name}")
    await ctx.reply(embed=e, view=DeobfView(source, ctx.author.id, top_name))


@bot.command(name="detector")
async def detector(ctx: commands.Context, *, url: str = None):
    if not await channel_ok(ctx, quiet=True):
        return
    source, err = await get_source(ctx, url)
    if source is None:
        return await ctx.reply(embed=make_embed("Could not read the script", err, C_ERR))
    results = detect(source.decode("utf-8", "ignore"))
    lines = [f"**{n}**\n`{bar(score_1_to_10(p))}` {score_1_to_10(p)}/10" for n, p in results[:5] if p > 0]
    top_name = results[0][0] if results else "Custom / Unknown"
    color, icon = OBF_STYLE.get(top_name, (C_DARK, None))
    e = make_embed("🔎 Detector", "\n\n".join(lines) or "No obfuscator detected.", color)
    if icon and lines:
        e.set_thumbnail(url=icon)
    await ctx.reply(embed=e)


@bot.command(name="stats")
async def stats(ctx: commands.Context):
    uptime = int(time.time() - getattr(bot, "launch_time", time.time()))
    e = make_embed("📊 Stats", None, C_BRAND)
    e.add_field(name="Uptime", value=fmt_uptime(uptime), inline=True)
    e.add_field(name="Latency", value=f"{round(bot.latency * 1000, 1)} ms", inline=True)
    e.add_field(name="Servers", value=str(len(bot.guilds)), inline=True)
    await ctx.reply(embed=e)


@bot.command(name="help")
async def help_cmd(ctx: commands.Context, *, command: str = None):
    if command:
        name = command.strip().lstrip(".").lower()
        info = COMMANDS.get(name)
        if not info:
            return await ctx.reply(embed=make_embed("Unknown command", f"`{name}` does not exist. Use `.help`.", C_ERR), delete_after=8)
        cat, usage, desc = info
        e = make_embed(f"Command · {name}", desc, C_BRAND)
        e.add_field(name="Usage", value=f"`{usage}`", inline=False)
        e.add_field(name="Category", value=f"{CATEGORIES[cat]['emoji']} {cat}", inline=True)
        return await ctx.reply(embed=e)
    start = "Tools"
    await ctx.reply(embed=help_embed(start, ctx.author), view=HelpView(ctx.author.id, start))


async def _logger_command(ctx: commands.Context, url, runner, label, filename):
    if not await channel_ok(ctx):
        return
    source, err = await get_source(ctx, url)
    if source is None:
        return await ctx.reply(embed=make_embed("Could not read the script", err, C_ERR), delete_after=8)
    msg = await ctx.reply(embed=working_embed(label))
    started = time.time()
    res, err = await runner(source)
    elapsed = time.time() - started
    if not res:
        return await msg.edit(embed=error_embed(label, err))
    await msg.edit(
        embed=result_embed(label, len(res), elapsed),
        attachments=[discord.File(fp=io.BytesIO(res), filename=filename)],
    )


@bot.command(name="l")
async def env_logger_cmd(ctx: commands.Context, *, url: str = None):
    await _logger_command(ctx, url, run_envlog, "Env Logger", "envlog_output.lua")


@bot.command(name="l2")
async def env_logger_2_cmd(ctx: commands.Context, *, url: str = None):
    await _logger_command(ctx, url, run_envlog2, "Env Logger 2", "envlog2_output.lua")


# ---------- HANDLERS ----------
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    if isinstance(error, commands.MissingPermissions):
        msg = "You need administrator permission for this command."
    else:
        msg = f"`{error!r}`"
    try:
        await ctx.reply(embed=make_embed("Error", msg, C_ERR), delete_after=10)
    except Exception:
        pass


@bot.event
async def on_ready():
    bot.launch_time = time.time()
    print(f"Bot online: {bot.user}", flush=True)
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name=".help · DropX"))
    try:
        await bot.tree.sync()
    except Exception:
        pass


async def main():
    print(f">>> LUNE={LUNE} exists={os.path.exists(LUNE)}", flush=True)
    print(f">>> ENVLOG_PATH={ENVLOG_PATH} exists={os.path.exists(ENVLOG_PATH)}", flush=True)
    print(f">>> ENVLOG2_PATH={ENVLOG2_PATH} exists={os.path.exists(ENVLOG2_PATH)}", flush=True)
    print(f">>> CONFIG_FILE={CONFIG_FILE}", flush=True)
    await start_web_server()
    await bot.start(TOKEN)


if __name__ == "__main__":
    asyncio.run(main())
