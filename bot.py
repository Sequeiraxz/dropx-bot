import os
import io
import asyncio
import tempfile
import re
import json
import math
import time
import platform
import traceback
import aiohttp
import discord
from collections import Counter
from discord.ext import commands
from aiohttp import web

TOKEN = os.environ.get("DISCORD_TOKEN")

DEOBF_DIR = os.environ.get("DEOBF_DIR", "./Prometheus-Deobfuscator-main")
MOONSEC_V2_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "moonsec-v2-deobfuscator")
MOONVEIL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "moonveil-deobf")
LUAOBFUSCATOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "luaobfuscator-deobf", "luaobfuscator")
NODE = os.environ.get("NODE", "node")
DEOBF_TIMEOUT = 600
CONFIG_FILE = "config.json"

HEADER = "Deobfuscate By DropX :)\n\n"
WEAREDEVS_ICON = "https://www.google.com/s2/favicons?domain=wearedevs.net&sz=128"
WEAREDEVS_EMOJI_ID = 1565837351769481216
MOONSEC_EMOJI_ID = 1566041038852718692
MOONSEC_ICON = f"https://cdn.discordapp.com/emojis/{MOONSEC_EMOJI_ID}.png"
MOONVEIL_EMOJI_ID = 1566062539962323085
MOONVEIL_ICON = f"https://cdn.discordapp.com/emojis/{MOONVEIL_EMOJI_ID}.png"
LUAOBF_EMOJI_ID = 1566411737727770714
LUAOBF_ICON = f"https://cdn.discordapp.com/emojis/{LUAOBF_EMOJI_ID}.png"

RAW_DOMAINS = [
    "https://pastebin.com/",
    "https://raw.githubusercontent.com/",
    "https://gist.githubusercontent.com/",
    "https://pastefy.app/",
    "https://paste.ee/r/",
    "https://rawscripts.net/raw/",
    "https://scriptblox.com/script/",
    "https://pandadevelopment.net/virtual/file/",
]
ROBLOX_UA = "Roblox/WinInetRobloxApp/0.673.0.6730711 (GlobalDist; RobloxDirectDownload)"
PROXY = None

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {"channel_id": None}

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)

config = load_config()

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=".", intents=intents)
bot.remove_command("help")

_moonsec_lock = asyncio.Lock()
_moonveil_lock = asyncio.Lock()

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
        (8,  re.compile(r'bit32\.rshift')),
        (30, re.compile(r"local\s+\w\s*=\s*\{(?:\s*'(?:\\[0-9]{2,3}){6,}'[;,]?\s*){5,}")),
        (25, re.compile(r'local\s+function\s+\w+\s*\(\s*\w+\s*\)[\s\S]{0,300}string\.char\s*\([\s\S]{0,200}string\.byte', re.DOTALL)),
        (20, re.compile(r'\bg\s*\[\s*\d+\s*\]')),
        (18, re.compile(r'string\.byte\s*\(\s*\w+\s*,\s*\w+\s*\)\s*[-+^]\s*\w+')),
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
    "MoonSec V3": [
        (30, re.compile(r'\(\[\[This file was protected with MoonSec V3\]\]\)')),
        (30, re.compile(r'\:gsub\s*\(\s*\'\.+\'\s*,\s*\(function\s*\(a\)')),
        (20, re.compile(r'_[A-Z][a-zA-Z]{6,}\s*=\s*a\s*;')),
        (25, re.compile(r'return\s*\(function\s*\(\w,\.\.\.\)local\s+\w;local\s+\w;')),
        (15, re.compile(r'while\s+n<\s*0x[0-9a-f]+\s+and\s+e%0x[0-9a-f]+<0x[0-9a-f]+')),
        (20, re.compile(r'\bk\s*\(\s*\d{2,3}\s*,\s*"[A-Za-z0-9_()\^>?#_~!|]{20,}"')),
        (15, re.compile(r'l\.[a-zA-Z_]{6,}\s*\(')),
        (15, re.compile(r'd\s*=\s*"(?:\\[0-9]{1,3}){10,}"')),
        (12, re.compile(r'local\s+e\s*=\s*0x01\s+local\s+function\s+k')),
    ],
    "Luraph 14": [
        (50, re.compile(r'--\s*This file was protected using Luraph Obfuscator v14')),
        (35, re.compile(r'return\s*\(\s*\{[A-Z]{1,3}=bit32\.\w+')),
        (30, re.compile(r'0[Xx][0-9a-fA-F]+_+[0-9a-fA-F]*')),
        (25, re.compile(r'0[Bb][01_]{3,}')),
        (25, re.compile(r'for\s+\w\s*=\s*0[Xx][0-9a-fA-F_]+\s*,\s*0[Xx][0-9a-fA-F_]+')),
        (20, re.compile(r'\w\[0[Xx][0-9a-fA-F]+__[0-9a-fA-F]*\]')),
        (20, re.compile(r'0[Xx][0-9a-fA-F]{1,4}_+[0-9a-fA-F]{1,4}')),
        (15, re.compile(r'\bbuffer\b')),
        (12, re.compile(r'coroutine\.wrap')),
        (20, re.compile(r'"[A-Za-z0-9$#@!%^&*()\[\]{}|<>?_=+\-.,;:\'"\\\/]{200,}"')),
    ],
    "Luraph 10": [
        (60, re.compile(r'--\s*This file was generated using Luraph Obfuscator v10')),
        (55, re.compile(r'"LPH\|[0-9A-Fa-f]{20,}"')),
        (40, re.compile(r'string\.char\s*\(\s*\w+\s*,\s*0\s*\)')),
        (35, re.compile(r':gsub\s*\(\s*"\.\."')),
        (30, re.compile(r'return\s+loadstring\s*\(')),
        (20, re.compile(r'\b[lI]{4,}\b')),
        (25, re.compile(r'l11i1lIil1lIIiiIill:sub\(5\)')),
        (20, re.compile(r'tonumber\s*\(\s*\w+\s*,\s*16\s*\)')),
    ],
    "IronBrew": [
        (10, re.compile(r"local\s+\w+=string\.byte;local\s+\w+=string\.char;local\s+\w+=string\.sub;local\s+\w+=table\.concat;local\s+\w+=table\.insert;local\s+\w+=math\.ldexp")),
        (10, re.compile(r'local\s+function\s+\w+\(\w+\)\s*local\s+\w+,\s*\w+,\s*\w+\s*=\s*"",\s*"",\s*\{\}')),
        (45, re.compile(r"\b\w\('[0-9A-Z]{15,}'\)")),
        (10, re.compile(r"getfenv\s+or\s+function\s*\(\s*\)\s*return\s+_ENV\s+end")),
        (10, re.compile(r"unpack\s+or\s+table\.unpack")),
    ],
    "25ms Obfuscator": [
        (30, re.compile(r'(?:\\\d{2,3}){15,}')),
        (35, re.compile(r'"[A-Za-z0-9+/=]{120,}"')),
        (25, re.compile(r'string\.gsub\s*\(\s*".-",\s*function')),
        (30, re.compile(r'\{(?:\d+,){40,}\d+\}')),
        (20, re.compile(r'math\.ldexp|bit32\.(?:bxor|lshift|rshift)')),
        (15, re.compile(r'(?:\(\s*\d+\s*[\+\-\*/]\s*\d+\s*\)){5,}')),
        (25, re.compile(r'return\s*\(\s*function\s*\(')),
        (20, re.compile(r'^.{400,}$', re.MULTILINE)),
        (15, re.compile(r'(?:[\+\-\*/%^&|]{1}){20,}')),
        (40, re.compile(r'(?:\\\d{2,3}){25,}')),
        (25, re.compile(r'string\.char\s*\(\s*(?:\d+,){10,}\d+\s*\)')),
    ],
    "IronBrew3": [
        (30, re.compile(r"^--ironbrew3:tm")),
        (30, re.compile(r"return\(function\(\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+,\w+")),
        (40, re.compile(r"bit32\s+or\s+bit")),
        (35, re.compile(r"(?:[0-9A-Fa-f]{2}){15,}")),
        (30, re.compile(r"\{(?:\d+,){50,}\d+\},\s*0,\s*255,\s*1\)")),
        (20, re.compile(r"math\.max,math\.atan2,string\.sub,math\.ceil,string\.len")),
    ],
    "LuaObfuscator VM": [
        (50, re.compile(r'local\s+v0\s*=\s*tonumber\s*;\s*local\s+v1\s*=\s*string\.byte')),
        (35, re.compile(r'local\s+function\s+v15\s*\(v16,v17')),
        (50, re.compile(r'return\s+v15\s*\(\s*"LOL!')),
        (30, re.compile(r'[0-9A-F]{2}3Q00[0-9A-F]')),
        (30, re.compile(r'[0-9A-F]{2}2Q00[0-9A-F]')),
        (20, re.compile(r'local\s+function\s+v29\s*\(v57')),
        (15, re.compile(r'v\d+\s*=\s*unpack\s+or\s+table\.unpack')),
        (15, re.compile(r'local\s+v8\s*=\s*math\.ldexp')),
        (15, re.compile(r'getfenv\s+or\s+function\s*\(\s*\)\s*return\s+_ENV')),
    ],
    "WynFuscator": [
        (10, re.compile(r'--\s*Protected by wYnFuscate')),
        (10, re.compile(r'wynfuscate\.com')),
        (30, re.compile(r'local\s+cd\s*=\s*"[A-Za-z0-9^*.?()\[\]!@#$%&_~|<>{}`\'\-]{80,}"')),
        (30, re.compile(r'local\s+cG\s*=\s*65536')),
        (30, re.compile(r'local\s+cj\s*=\s*function\s*\(c8,c9,c4\)')),
        (25, re.compile(r'cg\[cj\(\d+,cT,5\)\]')),
        (20, re.compile(r'local\s+cl\s*=\s*"(?:\\[0-9]{1,3}){20,}"')),
        (15, re.compile(r'c0\s*=\s*4294967296')),
        (20, re.compile(r'\bcA\s*\(\s*\d+\s*\)')),
    ],
    "Hercules": [
        (10, re.compile(r'--\[Protected By Hercules')),
        (15, re.compile(r"'Protected By Hercules V1\.6 \| github\.com/zeusssz/hercules-obfuscator'")),
        (10, re.compile(r'hercules-obfuscator\.xyz')),
        (25, re.compile(r'local\s+[A-Z][a-z][A-Za-z]{6,}\s*,\s*[A-Z][a-z][A-Za-z]{6,}')),
        (30, re.compile(r'[A-Z][a-zA-Z]{6,}\s*=\s*ipairs\s*;')),
        (25, re.compile(r'[A-Z][a-zA-Z]{6,}\s*=\s*pairs\s*;')),
        (20, re.compile(r'if\s+false\s+then\s+local\s+\w+\s*=\s*\d+')),
        (20, re.compile(r'while\s+false\s+do\s+local\s+\w+\s*=\s*\d+\s+break\s+end')),
        (12, re.compile(r'math\.ldexp')),
        (50, re.compile(r"\('.*?\\\d+\\\d+'\)")),
        (15, re.compile(r'return\s+\(function\s*\(\.\.\.\)\s+local\s+[A-Z][a-z][A-Za-z]{5,}')),
    ],
    "MoonVeil": [
        (50, re.compile(r'--\s*This script was generated using the MoonVeil Obfuscator')),
        (40, re.compile(r'moonveil\.cc')),
        (35, re.compile(r'local\s+\w+,\w+,\w+,\w+=getmetatable,bit32\.bxor,pairs,type')),
        (30, re.compile(r'\(function\(\.\.\.\)return\{\[1\]=\{\.\.\.\},\[2\]=\w+\(\'#\',\.\.\.\)\}end\)')),
        (25, re.compile(r'return\s*\{[^}]*\[1\]\s*=\s*\{[^}]*\},\s*\[2\]\s*=\s*\w+\s*\(\s*\'#\'')),
        (30, re.compile(r"Ki=Ig\(Ki,'\[[\^A-Z]")),
        (25, re.compile(r'local\s+function\s+\w+\s*\(\w+,\w+,\w+\)\s*if\s+\w+>\w+\s+then\s+return\s+end\s+return\s+\w+\[\w+\]')),
        (25, re.compile(r'bit32\s*\.\s*lshift\s*,\s*bit32\s*\.\s*rshift\s*,\s*bit32\s*\.\s*band')),
        (20, re.compile(r"'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+/'.*gsub")),
        (20, re.compile(r'repeat\s+while\s+true\s+do\s+if\s+\w+<=[0-9]+\s+then\s+if\s+\w+<=[0-9]+')),
        (15, re.compile(r'Ng\[[\w-]+\]\s+or\s+\w+\([\w-]+,')),
    ],
    "77fuscator": [
        (60, re.compile(r'\[\[77fuscator\s+[\d.]+')),
        (30, re.compile(r'discord\.gg/[A-Za-z0-9]{8,}')),
        (35, re.compile(r'do\s+local\s+\w\s*=\s*\[\[77fuscator')),
        (30, re.compile(r'o,g,s,l,n,b,j,v,bb,m,r,bf=string\.byte,string\.char,string\.sub,table\.concat,math\.ldexp')),
        (25, re.compile(r'be=function\s*\(\w,\w+\)\s*local\s+\w+\s+local\s+\w+=3')),
        (25, re.compile(r'bd=function\s*\(\w\)\s*local\s+\w+,\w+,\w+,\w+,\w+,\w+,\w+\s+local\s+\w+=0')),
        (20, re.compile(r'bj=function\s*\(\s*\)\s*local\s+\w+,\w+\s+local\s+\w+=0')),
        (20, re.compile(r'getfenv\s+or\s+function\s*\(\s*\)\s+return\s+_ENV\s+end')),
        (20, re.compile(r'bg,bh=nil')),
        (15, re.compile(r'q=2\^32-1')),
        (15, re.compile(r'bh=function\s*\(\w,\w\)\s*if\s+\w<0\s+then\s+return\s+bg\(')),
    ],
    "Lunr": [
        (30, re.compile(r'--\s*This file was protected using Lunr')),
        (15, re.compile(r'discord\.gg/BGQkGUW2Qs')),
        (15, re.compile(r'\{`[A-Za-z0-9+/=]{6,}`\s*[;,]')),
        (10, re.compile(r'\blocal\s+(?:[lI1i]{4,})\s*=')),
        (20, re.compile(r'"(?:All warfare is based on deception|The supreme art of war|If you know the enemy)[^"]*Sun Tzu"')),
        (30, re.compile(r'error\s*\(\s*`Tamper Detected!`\s*\)')),
        (10, re.compile(r'setmetatable\s*\(\s*\{\s*\}\s*,\s*\{')),
        (15, re.compile(r'\(-\d{5,}\+\d{5,}\)')),
        (10, re.compile(r'getfenv\s+and\s+getfenv\(\)\s+or\s+_ENV')),
        (50, re.compile(r'lliilI1i\s*=')),
        (10, re.compile(r'`[A-Za-z0-9+/]{10,}={0,2}`')),
        (15, re.compile(r'pcall\s*\(\s*function\s*\(\s*\)[^)]{0,80}end\s*\)')),
    ],
    "LightRay": [
        (60, re.compile(r'"LPS\?[0-9A-Z]{30,}"')),
        (40, re.compile(r'return\s*\(\s*function\s*\(\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w,\w')),
        (30, re.compile(r'function\s*\(\s*vk\s*,\s*vB\s*,\s*DH\s*,\s*ZX')),
        (35, re.compile(r'0[Bb][01_]{8,}')),
        (25, re.compile(r'\bZV\b.*\bwhile\s*\(ZV\)\s*do\b', re.DOTALL)),
        (30, re.compile(r'vB\[0[BbXx][0-9a-fA-F_]{4,}\]')),
        (25, re.compile(r'0_[bBxX][0-9a-fA-F_]{4,}')),
        (20, re.compile(r'\bts\s*\(\s*0[xXbB][0-9a-fA-F_]+\s*,\s*vB\[')),
        (20, re.compile(r'\brY\s*\(\s*ts\s*\(')),
        (15, re.compile(r'\}\s*,\s*false\s*,\s*string\.sub\s*,\s*select\s*,\s*error')),
        (20, re.compile(r'string\.byte\s*,\s*tonumber\s*,\s*math\.ldexp\s*,\s*\.\.\.\s*\)\s*\(\.\.\.\s*\)\s*;')),
    ],
    "Unobfuscated": [
        (15, re.compile(r'--\s*[A-Za-z ]{5,}')),
        (20, re.compile(r'function\s+[a-zA-Z_][a-zA-Z0-9_]{3,}\s*\(')),
        (17, re.compile(r'\bprint\s*\(')),
        (15, re.compile(r'\bwarn\s*\(')),
        (15, re.compile(r'\brequire\s*\(')),
        (15, re.compile(r'\bfor\s+[a-zA-Z_]\w*\s*,\s*[a-zA-Z_]\w*\s+in\s+pairs\s*\(')),
        (15, re.compile(r'\bif\s+[a-zA-Z_]\w*\s*[=~<>]+\s*[a-zA-Z_\d"\']+\s+then\b')),
        (20, re.compile(r'\blocal\s+[a-zA-Z_][a-zA-Z0-9_]{3,}\s*=')),
        (15, re.compile(r'local\s+function\s+[a-zA-Z_]\w+\s*\(')),
        (10, re.compile(r'game\s*:\s*GetService\s*\(')),
        (10, re.compile(r'game\s*:\s*HttpGet\s*\(')),
        (12, re.compile(r'workspace\.')),
        (12, re.compile(r'script\.')),
    ],
}
_DEFINITELY_OBF = [
    re.compile(r'`[A-Za-z0-9+/]{10,}={0,2}`'),
    re.compile(r'error\s*\(\s*`Tamper Detected'),
    re.compile(r'lliilI1i'),
    re.compile(r'Protected_by_MoonSecV2'),
    re.compile(r'Protected By Hercules'),
    re.compile(r'This file was protected using Lunr'),
    re.compile(r'This file was protected using Luraph'),
    re.compile(r'This file was generated using Luraph Obfuscator'),
    re.compile(r'This script was generated using the MoonVeil'),
    re.compile(r'\[\[77fuscator'),
    re.compile(r'--ironbrew3:tm'),
    re.compile(r'return\s+v15\s*\(\s*"LOL!'),
    re.compile(r'[\u3480-\u34c0]{5,}'),
    re.compile(r'\b[lI1i]{5,}\b'),
    re.compile(r'All warfare is based on deception.*Sun Tzu'),
    re.compile(r'"LPS\?[0-9A-Z]{30,}"'),
    re.compile(r'0_[bBxX][0-9a-fA-F_]{6,}'),
    re.compile(r'wearedevs\.net/obfuscator'),
    re.compile(r'return\s*\(\s*function\s*\(\s*\.\.\.\s*\)\s*local\s+\w\s*=\s*\{\s*"(?:\\[0-9]{2,3}){6,}"'),
]

_WEAREDEVS_SIGNALS = [
    re.compile(r'wearedevs\.net/obfuscator'),
    re.compile(r'\[\[\s*v\d+\.\d+\.\d+\s+https?://'),
    re.compile(r'local\s+o\s*=\s*\{\s*"(?:\\[0-9]{2,3}){6,}"'),
]

def calc_entropy(data: str) -> float:
    if not data: return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def stat_features(code: str) -> dict:
    lines = code.splitlines()
    total_chars = len(code)
    if total_chars == 0: return {}
    avg_line = (sum(len(l) for l in lines) / len(lines)) if lines else 0
    long_lines = sum(1 for l in lines if len(l) > 500) / max(len(lines), 1)
    hex_count = len(re.findall(r'0x[0-9a-fA-F]+', code))
    num_esc = len(re.findall(r'\\[0-9]{2,3}', code))
    ops = len(re.findall(r'[+\-*/%^&|]', code))
    unicode_cnt = len(re.findall(r'[\u3480-\u34c0]{3,}', code))
    backtick_strings = len(re.findall(r'`[^`]{6,}`', code))
    il_names = len(re.findall(r'\b[lI1i]{4,}\b', code))
    bin_literals = len(re.findall(r'0[Bb][01_]{4,}', code))
    underscore_hex = len(re.findall(r'0_[bBxX][0-9a-fA-F_]{4,}', code))
    dq_numesc_strings = len(re.findall(r'"(?:\\[0-9]{2,3}){6,}"', code))
    return {
        "entropy": calc_entropy(code), "avg_line_length": avg_line, "long_line_ratio": long_lines,
        "hex_literal_density": hex_count / max(total_chars / 1000, 1), "numeric_escape_density": num_esc / max(total_chars / 1000, 1),
        "operator_density": ops / max(total_chars / 1000, 1), "unicode_ident_count": unicode_cnt,
        "backtick_string_count": backtick_strings, "il_name_count": il_names, "bin_literal_count": bin_literals,
        "underscore_hex_count": underscore_hex, "dq_numesc_strings": dq_numesc_strings,
    }

def is_wearedevs(code: str) -> bool:
    for pat in _WEAREDEVS_SIGNALS:
        try:
            if pat.search(code): return True
        except: pass
    return False

def stat_bonus(obf_name: str, stats: dict, is_wad: bool = False) -> float:
    bonus = 0.0
    ent = stats.get("entropy", 0); nesc = stats.get("numeric_escape_density", 0); avg_line = stats.get("avg_line_length", 0)
    long_line = stats.get("long_line_ratio", 0); unicode_cnt = stats.get("unicode_ident_count", 0); backtick_cnt = stats.get("backtick_string_count", 0)
    il_cnt = stats.get("il_name_count", 0); bin_cnt = stats.get("bin_literal_count", 0); us_hex = stats.get("underscore_hex_count", 0); dq_nesc = stats.get("dq_numesc_strings", 0)

    if obf_name == "Prometheus":
        if nesc > 5: bonus += 10
        if 4.5 < ent < 6.0: bonus += 5
        if nesc > 15: bonus += 15
        if is_wad: bonus -= 80
        if dq_nesc > 10: bonus -= 40
    elif obf_name == "WeAreDevs":
        if nesc > 10: bonus += 15
        if dq_nesc > 20: bonus += 25
        if 4.0 < ent < 5.5: bonus += 8
        if avg_line > 200: bonus += 10
    elif obf_name == "MoonSec V2":
        if unicode_cnt > 5: bonus += 20
    elif obf_name == "MoonSec V3":
        if avg_line > 300: bonus += 8
        if ent > 5.5: bonus += 5
    elif obf_name == "Luraph 14":
        if long_line > 0.1: bonus += 8
        if stats.get("hex_literal_density", 0) > 10: bonus += 6
    elif obf_name == "Luraph 10":
        if il_cnt > 10: bonus += 10
        if ent > 4.5: bonus += 5
    elif obf_name == "LightRay":
        if bin_cnt > 20: bonus += 15
        if us_hex > 10: bonus += 12
        if avg_line > 1000: bonus += 10
        if ent > 4.8: bonus += 5
    elif obf_name == "LuaObfuscator VM":
        if long_line > 0.5: bonus += 8
    elif obf_name == "WynFuscator":
        if avg_line > 500: bonus += 10
        if ent > 5.0: bonus += 5
    elif obf_name == "Hercules":
        if avg_line > 100: bonus += 5
    elif obf_name == "IronBrew":
        if stats.get("operator_density", 0) > 20: bonus += 5
    elif obf_name == "MoonVeil":
        if avg_line > 200: bonus += 8
        if ent > 5.0: bonus += 5
    elif obf_name == "77fuscator":
        if avg_line > 300: bonus += 8
    elif obf_name == "Lunr":
        if backtick_cnt > 10: bonus += 15
        if il_cnt > 20: bonus += 10
        if ent > 4.5: bonus += 5
    elif obf_name == "25ms Obfuscator":
        if nesc > 8: bonus += 12
        if avg_line > 250: bonus += 10
        if ent > 5.2: bonus += 6
        if is_wad: bonus -= 60
        if dq_nesc > 10: bonus -= 30
    elif obf_name == "Unobfuscated":
        if avg_line < 120: bonus += 10
        if ent < 4.5: bonus += 8
        if backtick_cnt > 5: bonus -= 30
        if il_cnt > 10: bonus -= 25
        if ent > 5.5: bonus -= 20
        if avg_line > 400: bonus -= 15
        if bin_cnt > 10: bonus -= 20
        if us_hex > 5: bonus -= 20
    return bonus

def is_definitely_obfuscated(code: str) -> bool:
    for pat in _DEFINITELY_OBF:
        try:
            if pat.search(code): return True
        except: pass
    return False

def detect(code):
    stats = stat_features(code)
    raw_scores = {}
    definitely_obf = is_definitely_obfuscated(code)
    wad = is_wearedevs(code)

    for obf_name, patterns in SIGNATURES.items():
        score = 0.0
        for weight, pattern in patterns:
            try:
                if pattern.search(code): score += weight
            except: pass
        score += stat_bonus(obf_name, stats, is_wad=wad)
        if obf_name == "Unobfuscated" and definitely_obf: score = 0.0
        raw_scores[obf_name] = max(score, 0.0)

    sorted_scores = sorted(raw_scores.items(), key=lambda x: x[1], reverse=True)
    top_name, top_score = sorted_scores[0]
    second_score = sorted_scores[1][1] if len(sorted_scores) > 1 else 0.0
    total = sum(raw_scores.values())

    if top_score <= 0 or top_score < 20:
        return [("Custom / Unknown", 0.0)]

    gap_ratio = top_score / max(second_score, 1)
    percentages = []
    for name, score in raw_scores.items():
        if score <= 0: confidence = 0.0
        elif name == top_name:
            dominance = score / max(total, 1)
            gap_bonus = min(gap_ratio / 3, 1.0)
            strength = min(score / 120, 1.0)
            confidence = (dominance * 55 + gap_bonus * 25 + strength * 20)
        else:
            relative = score / max(top_score, 1)
            suppress = min(gap_ratio / 2, 1.0)
            confidence = relative * 45 * (1 - suppress)
        confidence = round(min(max(confidence, 0), 99.9), 1)
        percentages.append((name, confidence))

    percentages.sort(key=lambda x: x[1], reverse=True)
    return percentages

def score_1_to_10(pct: float) -> int:
    s = int(round(pct / 10.0))
    return max(1, min(10, s))
# =====================================================================
# FIM DO DETECTOR
# =====================================================================
# --- Web server ---
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

# --- Desofuscadores ---
async def run_deobf(source: bytes):
    with tempfile.TemporaryDirectory() as tmp:
        in_path = os.path.join(tmp, "input.lua")
        out_path = os.path.join(tmp, "out.lua")
        with open(in_path, "wb") as f: f.write(source)
        try:
            proc = await asyncio.create_subprocess_exec(NODE, "bin/pdeobf.js", in_path, "-o", out_path, cwd=DEOBF_DIR, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=DEOBF_TIMEOUT)
        except asyncio.TimeoutError: return None, f"timeout ({DEOBF_TIMEOUT}s)"
        except FileNotFoundError: return None, "Node.js not found"
        if proc.returncode != 0 or not os.path.exists(out_path): return None, stderr.decode("utf-8", "replace")[-1200:]
        with open(out_path, "rb") as f: return f.read(), ""

async def run_moonsec_v2(source: bytes):
    async with _moonsec_lock:
        with tempfile.TemporaryDirectory() as tmp:
            in_path = os.path.join(tmp, "input.lua")
            with open(in_path, "wb") as f: f.write(source)
            try:
                proc = await asyncio.create_subprocess_exec("python", "main.py", in_path, cwd=MOONSEC_V2_DIR, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            except asyncio.TimeoutError: return None, "timeout (300s)"
            except FileNotFoundError: return None, "Python/main.py not found"
            out_path = os.path.join(MOONSEC_V2_DIR, "output.lua")
            if proc.returncode != 0 or not os.path.exists(out_path):
                msg = (stdout + stderr).decode("utf-8", "replace").strip()
                return None, msg[-1200:] or "failed with no output"
            with open(out_path, "rb") as f: result = f.read()
            try: os.remove(out_path)
            except: pass
            return result, ""

async def run_moonveil(source: bytes):
    async with _moonveil_lock:
        with tempfile.TemporaryDirectory() as tmp:
            in_path = os.path.join(tmp, "input.lua")
            out_path = os.path.join(tmp, "recovered.lua")
            with open(in_path, "wb") as f: f.write(source)
            try:
                proc = await asyncio.create_subprocess_exec("python", "-m", "moonveil", "deobfuscate", in_path, "-o", out_path, "--seconds", "120", cwd=MOONVEIL_DIR, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
            except asyncio.TimeoutError: return None, "timeout (180s)"
            except FileNotFoundError: return None, "Python/moonveil not found"
            if proc.returncode != 0 or not os.path.exists(out_path):
                msg = (stdout + stderr).decode("utf-8", "replace").strip()
                return None, msg[-1200:] or f"exit code {proc.returncode}"
            with open(out_path, "rb") as f: return f.read(), ""

async def run_luaobfuscator(source: bytes):
    async with _moonveil_lock:
        with tempfile.TemporaryDirectory() as tmp:
            in_path = os.path.join(tmp, "input.lua")
            with open(in_path, "wb") as f: f.write(source)
            try:
                proc = await asyncio.create_subprocess_exec("node", "src/cli.js", in_path, "--stdout", cwd=LUAOBFUSCATOR_DIR, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
            except asyncio.TimeoutError: return None, "timeout (180s)"
            except FileNotFoundError: return None, "Node.js not found"
            if proc.returncode != 0: return None, stderr.decode("utf-8", "replace").strip()[-1200:] or f"exit code {proc.returncode}"
            return stdout, ""

# --- Dumper 6vms ---
DUMP_QUEUE = asyncio.Queue()

async def dump_worker():
    await bot.wait_until_ready()
    while True:
        job = await DUMP_QUEUE.get()
        message, source, filename = job
        try: await message.add_reaction("⏳")
        except: pass
        with tempfile.TemporaryDirectory() as tmp:
            in_path = os.path.join(tmp, "input.lua")
            out_path = os.path.join(tmp, "out.lua")
            with open(in_path, "wb") as f: f.write(source)
            try:
                proc = await asyncio.create_subprocess_exec("./lune", "run", "main.luau", in_path, f"out={out_path}", cwd=os.path.dirname(os.path.abspath(__file__)), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            except asyncio.TimeoutError:
                await message.reply("❌ **Skipped** — took over 120s"); await message.remove_reaction("⏳", bot.user); await message.add_reaction("⏱️"); DUMP_QUEUE.task_done(); continue
            except FileNotFoundError:
                await message.reply("❌ **Failed** — Lune is not installed on the server."); await message.remove_reaction("⏳", bot.user); await message.add_reaction("❌"); DUMP_QUEUE.task_done(); continue
            if proc.returncode != 0 or not os.path.exists(out_path):
                err = stderr.decode("utf-8", "replace")[-800:]
                await message.reply(f"❌ **Failed**\n```\n{err}\n```"); await message.remove_reaction("⏳", bot.user); await message.add_reaction("❌")
            else:
                with open(out_path, "rb") as f: result = f.read()
                if result.startswith(b"--err"):
                    err = result[5:].decode("utf-8", "replace").strip()
                    await message.reply(f"❌ **Engine error**\n```\n{err}\n```"); await message.remove_reaction("⏳", bot.user); await message.add_reaction("❌")
                else:
                    out_name = filename.replace(".lua", ".dump.lua").replace(".txt", ".dump.lua")
                    if not out_name.endswith(".lua"): out_name += ".dump.lua"
                    await message.reply(content=f"✅ **Dumped {filename}** • Made by Heartless", file=discord.File(fp=io.BytesIO(result), filename=out_name)); await message.remove_reaction("⏳", bot.user); await message.add_reaction("✅")
        DUMP_QUEUE.task_done()

async def fetch_url(url: str):
    if not re.match(r"^https?://", url): return None, "Invalid URL"
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status != 200: return None, f"HTTP {r.status}"
                return await r.read(), ""
    except Exception as e: return None, str(e)

# --- Verificações ---
def looks_like_prometheus(code):
    score = 0
    if "wearedevs.net/obfuscator" in code: score += 4
    if re.search(r'\[\[\s*v\d+\.\d+\.\d+\s+https?://', code): score += 3
    if re.search(r'return\s*\(function\s*\(\.\.\.\)\s*local\s+\w\s*=\s*\{', code): score += 3
    if re.search(r'local\s+o\s*=\s*\{\s*"(?:\\[0-9]{2,3}){6,}"', code): score += 2
    if "getfenv and getfenv() or _ENV" in code: score += 2
    if "bit32.rrotate" in code or "bit32.rshift" in code: score += 1
    return score >= 3

def looks_like_moonsec_v2(code):
    score = 0
    if "Protected_by_MoonSecV2" in code: score += 3
    if re.search(r'[\u3480-\u34c0]{5,}', code): score += 3
    if "_msec" in code: score += 2
    if re.search(r'#\[\[[^\]]{3,}\]\]', code): score += 1
    if "discord.gg/gQEH" in code: score += 1
    return score >= 3

def looks_like_moonveil(code):
    score = 0
    if "MoonVeil" in code or "moonveil" in code: score += 3
    if "moonveil.cc" in code: score += 3
    if re.search(r'\[1\]\s*=\s*\{', code) and re.search(r'\[2\]\s*=\s*\w+\s*\(\s*\'#\'', code): score += 3
    if "getmetatable,bit32.bxor,pairs,type" in code.replace(" ", ""): score += 2
    return score >= 3

def looks_like_luaobfuscator(code):
    score = 0
    if "LuaObfuscator" in code or "luaobfuscator" in code: score += 3
    if "local v0=string.char" in code or "local v0 = string.char" in code: score += 3
    if "v3=bit32 or bit" in code or "v3 = bit32 or bit" in code: score += 2
    if re.search(r'v7\s*=\s*function', code) and "string.byte" in code: score += 2
    return score >= 3

# --- Botões ---
class PrometheusButton(discord.ui.Button):
    def __init__(self, enabled=True):
        super().__init__(label="Prometheus", style=discord.ButtonStyle.secondary, emoji=discord.PartialEmoji(name="wearedevs", id=WEAREDEVS_EMOJI_ID), disabled=not enabled, row=0)
    async def callback(self, interaction: discord.Interaction):
        try:
            src = getattr(self.view, "source", None)
            if not src: return await interaction.response.send_message("Script not found.", ephemeral=True)
            if not looks_like_prometheus(src.decode("utf-8", "ignore")):
                return await interaction.response.send_message(embed=discord.Embed(title="Prometheus — Verification Failed", description="This script does not look like Prometheus/WeAreDevs.", color=0xE74C3C).set_footer(text="Made by Heartless"), ephemeral=True)
            self.view.stop()
            await interaction.response.edit_message(content="Deobfuscating with Prometheus...", embed=None, view=None)
            res, err = await run_deobf(src)
            if not res: return await interaction.followup.send(f"Failed:\n```\n{err}\n```")
            final = (HEADER + res.decode("utf-8", "replace")).encode("utf-8")
            await interaction.followup.send(content=f"Deobfuscated — {len(final)} bytes\nMade by Heartless", file=discord.File(fp=io.BytesIO(final), filename="deobfuscated.txt"))
        except Exception as e: traceback.print_exc(); await interaction.followup.send(f"Error: `{e!r}`", ephemeral=True)

class MoonSecV2Button(discord.ui.Button):
    def __init__(self, enabled=True):
        super().__init__(label="MoonSec V2", style=discord.ButtonStyle.secondary, emoji=discord.PartialEmoji(name="moonsec", id=MOONSEC_EMOJI_ID), disabled=not enabled, row=0)
    async def callback(self, interaction: discord.Interaction):
        try:
            src = getattr(self.view, "source", None)
            if not src: return await interaction.response.send_message("Script not found.", ephemeral=True)
            if not looks_like_moonsec_v2(src.decode("utf-8", "ignore")):
                return await interaction.response.send_message(embed=discord.Embed(title="MoonSec V2 — Verification Failed", description="This script does not look like MoonSec V2.", color=0xE74C3C).set_footer(text="Made by Heartless"), ephemeral=True)
            self.view.stop()
            embed = discord.Embed(title="DropX — MoonSec V2", description="Deobfuscating...", color=0x2ECC71).set_author(name="MoonSec V2", icon_url=MOONSEC_ICON).set_footer(text="Made by Heartless")
            await interaction.response.edit_message(content=None, embed=embed, view=None)
            res, err = await run_moonsec_v2(src)
            if not res: return await interaction.followup.send(f"Failed:\n```\n{err}\n```")
            await interaction.followup.send(embed=discord.Embed(title="DropX — MoonSec V2", description=f"Deobfuscated — {len(res)} bytes", color=0x2ECC71).set_author(name="MoonSec V2", icon_url=MOONSEC_ICON).set_footer(text="Made by Heartless"), file=discord.File(fp=io.BytesIO(res), filename="deobfuscated.lua"))
        except Exception as e: traceback.print_exc(); await interaction.followup.send(f"Error: `{e!r}`", ephemeral=True)

class MoonVeilButton(discord.ui.Button):
    def __init__(self, enabled=True):
        super().__init__(label="MoonVeil", style=discord.ButtonStyle.secondary, emoji=discord.PartialEmoji(name="moonveil", id=MOONVEIL_EMOJI_ID), disabled=not enabled, row=0)
    async def callback(self, interaction: discord.Interaction):
        try:
            src = getattr(self.view, "source", None)
            if not src: return await interaction.response.send_message("Script not found.", ephemeral=True)
            if not looks_like_moonveil(src.decode("utf-8", "ignore")):
                return await interaction.response.send_message(embed=discord.Embed(title="MoonVeil — Verification Failed", description="This script does not look like MoonVeil.", color=0xE74C3C).set_footer(text="Made by Heartless"), ephemeral=True)
            self.view.stop()
            await interaction.response.edit_message(content="Deobfuscating with MoonVeil...", embed=None, view=None)
            res, err = await run_moonveil(src)
            if not res:
                try: j = json.loads(err)
                except: j = None
                if j and j.get("status") == "unsupported":
                    return await interaction.followup.send(embed=discord.Embed(title="MoonVeil — Unsupported", description=f"Reason: `{j.get('reason')}`", color=0xE74C3C).set_footer(text="Made by Heartless"))
                return await interaction.followup.send(f"Failed:\n```\n{err}\n```")
            await interaction.followup.send(content=f"Deobfuscated — {len(res)} bytes\nMade by Heartless", file=discord.File(fp=io.BytesIO(res), filename="deobfuscated.lua"))
        except Exception as e: traceback.print_exc(); await interaction.followup.send(f"Error: `{e!r}`", ephemeral=True)

class LuaObfuscatorButton(discord.ui.Button):
    def __init__(self, enabled=True):
        super().__init__(label="LuaObfuscator", style=discord.ButtonStyle.secondary, emoji=discord.PartialEmoji(name="luaobf", id=LUAOBF_EMOJI_ID), disabled=not enabled, row=0)
    async def callback(self, interaction: discord.Interaction):
        try:
            src = getattr(self.view, "source", None)
            if not src: return await interaction.response.send_message("Script not found.", ephemeral=True)
            if not looks_like_luaobfuscator(src.decode("utf-8", "ignore")):
                return await interaction.response.send_message(embed=discord.Embed(title="LuaObfuscator — Verification Failed", description="This script does not look like LuaObfuscator.", color=0xE74C3C).set_footer(text="Made by Heartless"), ephemeral=True)
            self.view.stop()
            await interaction.response.edit_message(content="Deobfuscating with LuaObfuscator...", embed=None, view=None)
            res, err = await run_luaobfuscator(src)
            if not res: return await interaction.followup.send(f"Failed:\n```\n{err}\n```")
            await interaction.followup.send(content=f"Deobfuscated — {len(res)} bytes\nMade by Heartless", file=discord.File(fp=io.BytesIO(res), filename="deobfuscated.lua"))
        except Exception as e: traceback.print_exc(); await interaction.followup.send(f"Error: `{e!r}`", ephemeral=True)

class DeobfView(discord.ui.View):
    def __init__(self, source: bytes, prometheus_enabled=True, moonsec_enabled=True, moonveil_enabled=True, luaobf_enabled=True):
        super().__init__(timeout=600)
        self.source = source
        self.add_item(PrometheusButton(enabled=prometheus_enabled))
        self.add_item(MoonSecV2Button(enabled=moonsec_enabled))
        self.add_item(MoonVeilButton(enabled=moonveil_enabled))
        self.add_item(LuaObfuscatorButton(enabled=luaobf_enabled))

async def get_source(ctx: commands.Context, url: str = None):
    if ctx.message.attachments:
        att = ctx.message.attachments[0]
        if not att.filename.endswith((".txt", ".lua", ".luau")): return None, "Attachment must be .txt/.lua/.luau"
        if att.size > 5 * 1024 * 1024: return None, "File > 5 MiB."
        return await att.read(), ""
    elif url:
        source, err = await fetch_url(url.strip())
        if source is None: return None, f"Could not fetch URL: {err}"
        if len(source) > 5 * 1024 * 1024: return None, "File > 5 MiB."
        return source, ""
    return None, "Usage: attach file or URL."

# --- Comandos ---
@bot.command(name="alojar")
@commands.has_permissions(administrator=True)
async def alojar(ctx: commands.Context):
    config["channel_id"] = ctx.channel.id
    save_config(config)
    await ctx.reply("Bot hosted successfully.", delete_after=10)

@bot.command(name="l")
async def dump_cmd(ctx: commands.Context, *, url: str = None):
    source, err = await get_source(ctx, url)
    if source is None: return await ctx.reply(err, delete_after=5)
    await ctx.message.add_reaction("🕓")
    filename = ctx.message.attachments[0].filename if ctx.message.attachments else "script.lua"
    await DUMP_QUEUE.put((ctx.message, source, filename))

@bot.command(name="deobf")
async def deobf(ctx: commands.Context, *, url: str = None):
    if config["channel_id"] is None: return await ctx.reply("Bot not hosted. Use .alojar")
    if ctx.channel.id != config["channel_id"]: return await ctx.reply("Wrong channel.")
    source, err = await get_source(ctx, url)
    if source is None: return await ctx.reply(err, delete_after=5)
    results = detect(source.decode("utf-8", "ignore"))
    top_name, top_pct = results[0] if results else ("Custom / Unknown", 0.0)
    is_prometheus = (top_name in ("Prometheus", "WeAreDevs"))
    is_moonsec = (top_name == "MoonSec V2")
    is_moonveil = (top_name == "MoonVeil")
    is_luaobf = (top_name in ("LuaObfuscator VM", "LuaObfuscator"))
    if is_prometheus: desc = f"**Detected:** {top_name} ({score_1_to_10(top_pct)}/10)\n\nClick **Prometheus** to deobfuscate."
    elif is_moonsec: desc = f"**Detected:** {top_name} ({score_1_to_10(top_pct)}/10)\n\nClick **MoonSec V2** to deobfuscate."
    elif is_moonveil: desc = f"**Detected:** {top_name} ({score_1_to_10(top_pct)}/10)\n\nClick **MoonVeil** to deobfuscate."
    elif is_luaobf: desc = f"**Detected:** {top_name} ({score_1_to_10(top_pct)}/10)\n\nClick **LuaObfuscator** to deobfuscate."
    else: desc = f"**Detected:** {top_name} ({score_1_to_10(top_pct)}/10)\n\nTry any deobfuscator."
    await ctx.reply(embed=discord.Embed(title="DropX Deobfuscator", description=desc, color=0x2ECC71).set_footer(text="Made by Heartless"), view=DeobfView(source))

@bot.command(name="detector")
async def detector(ctx: commands.Context, *, url: str = None):
    if config["channel_id"] is None: return await ctx.reply("Bot not hosted.")
    source, err = await get_source(ctx, url)
    if source is None: return await ctx.reply(err)
    results = detect(source.decode("utf-8", "ignore"))
    lines = [f"**{n}** — {score_1_to_10(p)}/10" for n, p in results[:5] if p > 0]
    await ctx.reply(embed=discord.Embed(title="Detector", description="\n".join(lines), color=0x2B2D31).set_footer(text="Made by Heartless"))

@bot.command(name="stats")
async def stats(ctx: commands.Context):
    uptime = int(time.time() - getattr(bot, "launch_time", time.time()))
    await ctx.reply(embed=discord.Embed(title="Stats", description=f"Uptime: {uptime}s\nLatency: {round(bot.latency*1000, 1)} ms", color=0x2ECC71).set_footer(text="Made by Heartless"))

@bot.command(name="help")
async def help_cmd(ctx: commands.Context):
    e = discord.Embed(title="DropX Commands", description="Prefix: `.`", color=0x2ECC71)
    e.add_field(name="`.alojar`", value="Host bot", inline=False)
    e.add_field(name="`.deobf`", value="Deobfuscate (Prometheus, MoonSec, MoonVeil, LuaObf)", inline=False)
    e.add_field(name="`.l`", value="Universal dumper (6vms)", inline=False)
    e.add_field(name="`.detector`", value="Detect obfuscator", inline=False)
    e.add_field(name="`.stats`", value="Bot stats", inline=False)
    e.set_footer(text="Made by Heartless")
    await ctx.reply(embed=e)

# --- Handlers e Arranque ---
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound): return
    try: await ctx.reply(f"Error: `{error!r}`", delete_after=10)
    except: pass

@bot.event
async def on_ready():
    bot.launch_time = time.time()
    print(f"Bot online: {bot.user}", flush=True)
    try: await bot.tree.sync()
    except: pass

async def main():
    print(">>> MAIN STARTED", flush=True)
    await start_web_server()
    asyncio.create_task(dump_worker())
    await bot.start(TOKEN)

if __name__ == "__main__":
    asyncio.run(main())
