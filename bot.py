import os
import io
import asyncio
import tempfile
import re
import json
import aiohttp
import discord
from discord.ext import commands
from aiohttp import web
# from detector import detect, print_report

# ⚠️ Usa a variável de ambiente do Render (DISCORD_TOKEN)
TOKEN = os.environ.get("DISCORD_TOKEN", "MTU2NTc3NDk0MjA4NjEwMzEyMg.GwcgxL.9d50odJ3Ujrf0nrIcToLXPFW64yhA1E7hPLJlQ")

DEOBF_DIR = os.environ.get("DEOBF_DIR", "./Prometheus-Deobfuscator-main")
NODE = os.environ.get("NODE", "node")
DEOBF_TIMEOUT = 600
CONFIG_FILE = "config.json"

HEADER = "Deobfuscate By DropX :)\n\n"
WEAREDEVS_ICON = "https://www.google.com/s2/favicons?domain=wearedevs.net&sz=128"
WEAREDEVS_EMOJI_ID = 1565837351769481216

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

# --- Servidor Web para o Render ---
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
    print(f"Servidor web a correr na porta {port}")

# --- Desofuscador ---
async def run_deobf(source: bytes) -> tuple[bytes | None, str]:
    with tempfile.TemporaryDirectory() as tmp:
        in_path = os.path.join(tmp, "input.lua")
        out_path = os.path.join(tmp, "out.lua")
        with open(in_path, "wb") as f:
            f.write(source)
        try:
            proc = await asyncio.create_subprocess_exec(
                NODE, "bin/pdeobf.js", in_path, "-o", out_path,
                cwd=DEOBF_DIR, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=DEOBF_TIMEOUT)
        except asyncio.TimeoutError:
            return None, f"timeout ({DEOBF_TIMEOUT}s)"
        except FileNotFoundError:
            return None, "Node.js não encontrado"
        if proc.returncode != 0 or not os.path.exists(out_path):
            return None, stderr.decode("utf-8", "replace")[-1200:]
        with open(out_path, "rb") as f:
            return f.read(), ""

async def fetch_url(url: str) -> tuple[bytes | None, str]:
    if not re.match(r"^https?://", url):
        return None, "URL inválido"
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status != 200:
                    return None, f"HTTP {r.status}"
                return await r.read(), ""
    except Exception as e:
        return None, str(e)

# --- Botões e Comando ---
class PrometheusButton(discord.ui.Button):
    def __init__(self, enabled=True):
        super().__init__(label="Prometheus", style=discord.ButtonStyle.secondary, emoji=discord.PartialEmoji(name="wearedevs", id=WEAREDEVS_EMOJI_ID), disabled=not enabled)

    async def callback(self, interaction: discord.Interaction):
        source = getattr(self.view, "source", None)
        if source is None:
            await interaction.response.send_message("❌ script não encontrado.", ephemeral=True)
            return

        self.view.stop()
        await interaction.response.edit_message(content="⏳ **DropX pode demorar um pouco a desofuscar. Por favor, aguarda...**", embed=None, view=None)

        result, err = await run_deobf(source)
        
        if result is None:
            await interaction.followup.send(f"❌ falhou:\n```\n{err}\n```", ephemeral=False)
            return
        if len(result) > 8 * 1024 * 1024:
            await interaction.followup.send("❌ output > 8 MiB.", ephemeral=False)
            return
            
        final = (HEADER + result.decode("utf-8", "replace")).encode("utf-8")
        await interaction.followup.send(content=f"✅ desofuscado — {len(final)} bytes", file=discord.File(fp=io.BytesIO(final), filename="deobfuscated.txt"))

class DeobfView(discord.ui.View):
    def __init__(self, source: bytes, enabled=True):
        super().__init__(timeout=600)
        self.source = source
        self.add_item(PrometheusButton(enabled=enabled))

# --- Comando para Alojar o Bot no Canal ---
@bot.command(name="alojar")
@commands.has_permissions(administrator=True)
async def alojar(ctx: commands.Context):
    config["channel_id"] = ctx.channel.id
    save_config(config)
    try:
        await ctx.message.delete()
    except:
        pass
    await ctx.reply(f"✅ **Bot alojado com sucesso!**\nA partir de agora, o bot só vai responder a comandos neste canal ({ctx.channel.mention}).", delete_after=10)

@alojar.error
async def alojar_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.reply("❌ Apenas administradores podem usar este comando.", delete_after=5)

# --- Comando de Deobfuscar (com verificação de canal e detector) ---
@bot.command(name="deobf")
async def deobf(ctx: commands.Context, *, url: str = None):
    if config["channel_id"] is None:
        await ctx.reply("❌ O bot ainda não foi alojado. Pede a um admin para usar `.alojar` neste canal.", delete_after=5)
        return
        
    if ctx.channel.id != config["channel_id"]:
        await ctx.reply("❌ Este bot só pode ser usado no canal onde foi alojado.", delete_after=5)
        return

    if ctx.message.attachments:
        att = ctx.message.attachments[0]
        if not att.filename.endswith((".txt", ".lua", ".luau")):
            await ctx.reply("❌ anexo tem de ser `.txt`/`.lua`/`.luau`.", delete_after=5)
            return
        if att.size > 5 * 1024 * 1024:
            await ctx.reply("❌ ficheiro > 5 MiB.", delete_after=5)
            return
        source = await att.read()
    elif url:
        source, err = await fetch_url(url.strip())
        if source is None:
            await ctx.reply(f"❌ não consegui obter o URL: {err}", delete_after=5)
            return
        if len(source) > 5 * 1024 * 1024:
            await ctx.reply("❌ ficheiro > 5 MiB.", delete_after=5)
            return
    else:
        await ctx.reply("❌ uso: `.deobf` + anexo `.txt`/`.lua` **ou** `.deobf <url_raw>`", delete_after=5)
        return

    try:
        await ctx.message.delete()
    except:
        pass

    # --- TESTE TEMPORÁRIO SEM DETECTOR ---
    top_name = "Prometheus"
    top_pct = 100
    is_prometheus = True

    if is_prometheus:
        desc = f"**Ofuscador detetado:** Prometheus (WeAreDevs)\n**Confiança:** {top_pct}%\n\nClica no botão abaixo para desofuscar."
    else:
        desc = f"**Ofuscador detetado:** {top_name}\n**Confiança:** {top_pct}%\n\n❌ **Este desofuscador ainda não está disponível neste bot.**"

    embed = discord.Embed(title="DropX Detector & Deobfuscator", description=desc, color=0x2B2D31)
    embed.set_author(name="Prometheus (WeAreDevs)", icon_url=WEAREDEVS_ICON)
    await ctx.reply(embed=embed, view=DeobfView(source, enabled=is_prometheus))

@bot.event
async def on_ready():
    print(f"Bot ligado: {bot.user}")
    try:
        await bot.tree.sync()
    except Exception as e:
        print(f"Erro sync: {e}")

async def main():
    await start_web_server()
    await bot.start(TOKEN)

if __name__ == "__main__":
    asyncio.run(main())
