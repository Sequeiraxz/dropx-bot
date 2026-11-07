-- envlog3.luau  (v3.1)  -- ficheiro completo, pronto a colar
-- Env logger / sandbox para análise de scripts ofuscados (lune 0.11, Luau, Lua 5.1/LuaJIT como fallback)
-- Compatível com WeAreDevs, Prometheus, MoonSec, MoonVeil, Luraph, LuaObfuscator, etc.
-- __SOURCE é injetado pelo bot.py antes deste ficheiro correr (global ou local).
-- Opcional: __ENVLOG_CONFIG = { MAX_PRINTS = 5000, TICKS = 10, ... } para sobrepor a CONFIG abaixo.
--
-- Novidades da v3.1 face à v3.0 (envlog2):
--   * captura de strings descodificadas (string.char, table.concat, gsub, format, reverse, base64)
--   * stubs universais para globais capitalizadas desconhecidas (Path2DControlPoint, ...)
--   * regista erros engolidos por pcall/xpcall (anti-tamper / anti-sandbox)
--   * orçamento de CPU em tempo real (corta loops sem wait)

local R = {
	print = print, pcall = pcall, xpcall = xpcall, tostring = tostring, tonumber = tonumber,
	type = type, typeof = typeof or type, select = select, pairs = pairs, ipairs = ipairs, next = next,
	setmetatable = setmetatable, getmetatable = getmetatable, rawget = rawget, rawset = rawset,
	rawequal = rawequal, error = error, require = require, load = load, loadstring = loadstring,
	getfenv = getfenv, setfenv = setfenv, newproxy = newproxy,
	unpack = (table and table.unpack) or unpack, debug = debug,
	create = coroutine.create, resume = coroutine.resume, yield = coroutine.yield,
	status = coroutine.status, running = coroutine.running,
	format = string.format, sub = string.sub, rep = string.rep, gsub = string.gsub, byte = string.byte,
	char = string.char, find = string.find, match = string.match, gmatch = string.gmatch,
	lower = string.lower, upper = string.upper,
	concat = table.concat, insert = table.insert, remove = table.remove, sort = table.sort,
	floor = math.floor, ceil = math.ceil, abs = math.abs, max = math.max, min = math.min,
	sqrt = math.sqrt, huge = math.huge,
	clock = (os and os.clock) or function() return 0 end,
	os_time = os and os.time, os_date = os and os.date,
}

local CONFIG = {
	MAX_PRINTS = 2000,        -- prints/warns guardados
	MAX_TRACE = 5000,         -- linhas de trace
	MAX_EVENTS = 1000,        -- eventos (http, remotes, ficheiros...)
	MAX_ENTRY_CHARS = 20000,  -- tamanho máximo de cada print
	MAX_OUTPUT_CHARS = 500000,
	MAX_LOADS = 200,          -- loadstring distintos guardados
	MAX_RESUMES = 30000,      -- resumes de threads (scheduler)
	MAX_WAITS = 20000,        -- chamadas a wait antes de abortar
	MAX_VIRTUAL_TIME = 600,   -- segundos virtuais
	TICKS = 5,                -- quantas vezes disparar Heartbeat/RenderStepped
	FIRE_ALL_SIGNALS = false, -- true = dispara qualquer :Connect uma vez com um mock
	TRACE_ENABLED = true,
	EXECUTOR_NAME = "envlog3",
	EXECUTOR_VERSION = "3.1",
	BASE_TIME = 1700000000,
	MAX_STRINGS = 3000,       -- strings descodificadas guardadas
	MIN_STRING_LEN = 6,
	MAX_CPU_SECONDS = 20,     -- corta loops sem wait (relógio real)
	AUTO_STUB_UPPER = true,   -- globais Capitalizadas desconhecidas -> stub
	MAX_SWALLOWED = 300,      -- erros engolidos por pcall guardados
}
do
	local uc = __ENVLOG_CONFIG
	if R.type(uc) == "table" then
		for k, v in R.pairs(uc) do CONFIG[k] = v end
	end
end

-- ---------- source ----------
local SOURCE = __SOURCE
if R.type(SOURCE) ~= "string" then SOURCE = "" end
if SOURCE == "" then
	-- uso manual: lune run envlog3.luau -- ficheiro.lua
	R.pcall(function()
		local process = R.require("@lune/process")
		local fs = R.require("@lune/fs")
		local path = process.args and process.args[1]
		if path then SOURCE = fs.readFile(path) end
	end)
end
if R.sub(SOURCE, 1, 3) == "\239\187\191" then SOURCE = R.sub(SOURCE, 4) end
if R.sub(SOURCE, 1, 2) == "#!" then SOURCE = "--" .. SOURCE end

-- ---------- utilitários ----------
local function safe_tostring(v)
	local ok, s = R.pcall(R.tostring, v)
	if ok and R.type(s) == "string" then return s end
	return "<tostring error>"
end

local function clip(s, n)
	n = n or CONFIG.MAX_ENTRY_CHARS
	if #s > n then return R.sub(s, 1, n) .. "...[+" .. (#s - n) .. " chars]" end
	return s
end

local ESC = { ["\n"] = "\\n", ["\r"] = "\\r", ["\t"] = "\\t", ['"'] = '\\"', ["\\"] = "\\\\" }
local function quote(s)
	return '"' .. R.gsub(s, '[%c"\\]', function(c) return ESC[c] or R.format("\\%03d", R.byte(c)) end) .. '"'
end

local function str_arg(v)
	if R.type(v) == "string" then return v end
	return safe_tostring(v)
end

local function hash32(s)
	local h = 5381
	for i = 1, #s do h = (h * 33 + R.byte(s, i)) % 4294967296 end
	return R.format("%08x", h)
end

-- ---------- estado global ----------
local vclock = 0 -- tempo virtual (segundos)
local function now() return CONFIG.BASE_TIME + vclock end

local prints, warns, errors_list, soft_errors = {}, {}, {}, {}
local trace, trace_dropped, last_trace = {}, 0, nil
local events, events_dropped = {}, 0
local loads, load_index = {}, {}
local counters = { loads = 0, requests = 0, remotes = 0, files = 0, waits = 0, resumes = 0, threads = 0 }
local undefined_globals, undefined_order = {}, {}
local written_globals, written_order = {}, {}
local instances_created = {}
local fake_fs = {}
local abort_reason = nil
local env_mode = "?"

local kinds = R.setmetatable({}, { __mode = "k" })       -- objeto -> nome do tipo (typeof)
local object_data = R.setmetatable({}, { __mode = "k" }) -- mock Instance -> dados

local fmt_value
fmt_value = function(v, depth)
	local t = R.type(v)
	if t == "string" then return quote(clip(v, 200)) end
	if t == "number" or t == "boolean" or t == "nil" then return safe_tostring(v) end
	if t == "function" then return "<function>" end
	if t == "table" then
		local d = object_data[v]
		if d then return d.path end
		if kinds[v] then return safe_tostring(v) end
		depth = depth or 0
		if depth >= 2 then return "{...}" end
		local parts, n = {}, 0
		R.pcall(function()
			for k, val in R.pairs(v) do
				n = n + 1
				if n > 6 then parts[#parts + 1] = "..."; break end
				if R.type(k) == "number" then
					parts[#parts + 1] = fmt_value(val, depth + 1)
				else
					parts[#parts + 1] = safe_tostring(k) .. "=" .. fmt_value(val, depth + 1)
				end
			end
		end)
		return "{" .. R.concat(parts, ", ") .. "}"
	end
	return "<" .. t .. ">"
end

local function fmt_args(...)
	local parts = {}
	for i = 1, R.select("#", ...) do parts[i] = fmt_value((R.select(i, ...))) end
	return R.concat(parts, ", ")
end

local function join_args(...)
	local parts = {}
	for i = 1, R.select("#", ...) do parts[i] = safe_tostring((R.select(i, ...))) end
	return R.concat(parts, " ")
end

local function record(tbl, ...)
	if #tbl >= CONFIG.MAX_PRINTS then return end
	tbl[#tbl + 1] = clip(join_args(...))
end

local function note_soft(msg)
	if #soft_errors < 200 then soft_errors[#soft_errors + 1] = clip(msg, 1000) end
end

local function trace_add(kind, text)
	if not CONFIG.TRACE_ENABLED then return end
	text = clip(text, 400)
	if last_trace and last_trace.kind == kind and last_trace.text == text then
		last_trace.n = last_trace.n + 1
		return
	end
	if #trace >= CONFIG.MAX_TRACE then trace_dropped = trace_dropped + 1; return end
	last_trace = { t = vclock, kind = kind, text = text, n = 1 }
	trace[#trace + 1] = last_trace
end

local function event(kind, text)
	if #events >= CONFIG.MAX_EVENTS then events_dropped = events_dropped + 1; return end
	events[#events + 1] = { t = vclock, kind = kind, text = clip(text, 4000) }
	trace_add("event", kind .. ": " .. clip(text, 200))
end

local function capture_source(code, label)
	if load_index[code] then return load_index[code] end
	if #loads >= CONFIG.MAX_LOADS then return nil end
	loads[#loads + 1] = { src = code, name = label, count = 0, hash = hash32(code), t = vclock }
	load_index[code] = #loads
	return #loads
end

-- ---------- fingerprint do ofuscador ----------
local FINGERPRINTS = {
	{ "WeAreDevs", "wearedevs.net" }, { "Prometheus", "Prometheus" }, { "MoonSec", "MoonSec" },
	{ "MoonVeil", "Moonveil" }, { "MoonVeil", "MoonVeil" }, { "Luraph", "Luraph" },
	{ "IronBrew", "IronBrew" }, { "LuaObfuscator.com", "luaobfuscator.com" },
	{ "Synapse Xen", "Synapse Xen" }, { "Boronide", "Boronide" }, { "PSU", "PSU|" },
	{ "Hercules", "Hercules" }, { "Aztup", "Aztup" },
}
local function fingerprint(src)
	local found, seen = {}, {}
	local head = R.sub(src, 1, 6000)
	for _, f in R.ipairs(FINGERPRINTS) do
		if not seen[f[1]] and R.find(head, f[2], 1, true) then
			seen[f[1]] = true
			found[#found + 1] = f[1]
		end
	end
	if R.sub(src, 1, 1) == "\27" then found[#found + 1] = "precompiled bytecode" end
	local _, esc = R.gsub(head, "\\%d%d?%d?", "")
	if esc > 200 then found[#found + 1] = "decimal-escaped strings" end
	if #src > 2000 and not R.find(R.sub(src, 1, 2000), "\n", 1, true) then
		found[#found + 1] = "minified/single-line"
	end
	return found
end

-- ---------- bit32 / bit ----------
local bit32_impl, bit_impl
do
	local function build_bit32()
		local M = 4294967296
		local function u32(x) return R.floor(R.tonumber(x) or 0) % M end
		local function bitop(a, b, f)
			a, b = u32(a), u32(b)
			local r, p = 0, 1
			for _ = 1, 32 do
				local x, y = a % 2, b % 2
				if f(x, y) then r = r + p end
				a = (a - x) / 2
				b = (b - y) / 2
				p = p * 2
			end
			return r
		end
		local function fand(x, y) return x == 1 and y == 1 end
		local function f_or(x, y) return x == 1 or y == 1 end
		local function fxor(x, y) return x ~= y end
		local B = {}
		B.band = function(...)
			local r = 4294967295
			for i = 1, R.select("#", ...) do r = bitop(r, (R.select(i, ...)), fand) end
			return r
		end
		B.bor = function(...)
			local r = 0
			for i = 1, R.select("#", ...) do r = bitop(r, (R.select(i, ...)), f_or) end
			return r
		end
		B.bxor = function(...)
			local r = 0
			for i = 1, R.select("#", ...) do r = bitop(r, (R.select(i, ...)), fxor) end
			return r
		end
		B.bnot = function(a) return 4294967295 - u32(a) end
		B.lshift = function(a, n)
			n = R.floor(R.tonumber(n) or 0)
			if n >= 32 or n <= -32 then return 0 end
			if n < 0 then return B.rshift(a, -n) end
			return (u32(a) * 2 ^ n) % M
		end
		B.rshift = function(a, n)
			n = R.floor(R.tonumber(n) or 0)
			if n >= 32 or n <= -32 then return 0 end
			if n < 0 then return B.lshift(a, -n) end
			return R.floor(u32(a) / 2 ^ n)
		end
		B.arshift = function(a, n)
			a = u32(a)
			n = R.floor(R.tonumber(n) or 0)
			if n >= 32 then return a >= 2147483648 and (M - 1) or 0 end
			local r = R.floor(a / 2 ^ n)
			if a >= 2147483648 and n > 0 then r = r + (M - 2 ^ (32 - n)) end
			return r
		end
		B.lrotate = function(a, n)
			n = R.floor(R.tonumber(n) or 0) % 32
			if n == 0 then return u32(a) end
			return B.lshift(a, n) + B.rshift(a, 32 - n)
		end
		B.rrotate = function(a, n) return B.lrotate(a, -(R.tonumber(n) or 0)) end
		B.rol, B.ror = B.lrotate, B.rrotate
		B.btest = function(...) return B.band(...) ~= 0 end
		B.extract = function(n, f, w)
			w = w or 1
			return B.band(B.rshift(n, f), 2 ^ w - 1)
		end
		B.replace = function(n, v, f, w)
			w = w or 1
			local mask = 2 ^ w - 1
			return B.bor(B.band(n, B.bnot(B.lshift(mask, f))), B.lshift(B.band(v, mask), f))
		end
		B.countlz = function(a)
			a = u32(a)
			if a == 0 then return 32 end
			local c = 0
			while a < 2147483648 do a = a * 2; c = c + 1 end
			return c
		end
		B.countrz = function(a)
			a = u32(a)
			if a == 0 then return 32 end
			local c = 0
			while a % 2 == 0 do a = a / 2; c = c + 1 end
			return c
		end
		B.byteswap = function(a)
			a = u32(a)
			return (a % 256) * 16777216 + (R.floor(a / 256) % 256) * 65536
				+ (R.floor(a / 65536) % 256) * 256 + R.floor(a / 16777216)
		end
		return B
	end

	if R.type(bit32) == "table" and bit32.band and bit32.bxor then
		bit32_impl = bit32 -- nativo do Luau: rápido e correto
	else
		bit32_impl = build_bit32()
	end
	local B = bit32_impl
	local function s32(x)
		x = B.band(x, 4294967295)
		if x >= 2147483648 then x = x - 4294967296 end
		return x
	end
	bit_impl = {
		tobit = s32,
		bnot = function(a) return s32(B.bnot(a)) end,
		band = function(...) return s32(B.band(...)) end,
		bor = function(...) return s32(B.bor(...)) end,
		bxor = function(...) return s32(B.bxor(...)) end,
		lshift = function(a, n) return s32(B.lshift(a, n)) end,
		rshift = function(a, n) return s32(B.rshift(a, n)) end,
		arshift = function(a, n) return s32(B.arshift(a, n)) end,
		rol = function(a, n) return s32(B.lrotate and B.lrotate(a, n) or B.rol(a, n)) end,
		ror = function(a, n) return s32(B.rrotate and B.rrotate(a, n) or B.ror(a, n)) end,
		bswap = function(a)
			return s32(B.bor(B.lshift(B.band(a, 255), 24), B.lshift(B.band(B.rshift(a, 8), 255), 16),
				B.lshift(B.band(B.rshift(a, 16), 255), 8), B.rshift(a, 24)))
		end,
		tohex = function(a, n)
			n = n or 8
			local h = R.format("%08x", B.band(a, 4294967295))
			if n < 0 then h = R.upper(h); n = -n end
			return R.sub(h, -n)
		end,
	}
end

-- ---------- datatypes ----------
local function make_vec(name, comps)
	local n = #comps
	local mt = {}
	local function comp(x, i)
		local t = R.type(x)
		if t == "number" then return x end
		if t == "table" then
			local c = R.rawget(x, comps[i])
			if R.type(c) == "number" then return c end
		end
		return 0
	end
	local function new(...)
		local args = { ... }
		local v = {}
		for i = 1, n do v[comps[i]] = R.tonumber(args[i]) or 0 end
		kinds[v] = name
		return R.setmetatable(v, mt)
	end
	local function map2(f)
		return function(a, b)
			local r = {}
			for i = 1, n do r[i] = f(comp(a, i), comp(b, i)) end
			return new(R.unpack(r, 1, n))
		end
	end
	local function map1(f)
		return function(a)
			local r = {}
			for i = 1, n do r[i] = f(comp(a, i)) end
			return new(R.unpack(r, 1, n))
		end
	end
	local function mag(a)
		local s = 0
		for i = 1, n do local c = comp(a, i); s = s + c * c end
		return R.sqrt(s)
	end
	mt.__add = map2(function(x, y) return x + y end)
	mt.__sub = map2(function(x, y) return x - y end)
	mt.__mul = map2(function(x, y) return x * y end)
	mt.__div = map2(function(x, y) return x / y end)
	mt.__idiv = map2(function(x, y) return R.floor(x / y) end)
	mt.__unm = map1(function(x) return -x end)
	mt.__eq = function(a, b)
		for i = 1, n do if comp(a, i) ~= comp(b, i) then return false end end
		return true
	end
	mt.__tostring = function(a)
		local p = {}
		for i = 1, n do p[i] = safe_tostring(comp(a, i)) end
		return R.concat(p, ", ")
	end
	local lower = {}
	for i = 1, n do lower[R.lower(comps[i])] = comps[i] end
	local methods = {
		Dot = function(a, b)
			local s = 0
			for i = 1, n do s = s + comp(a, i) * comp(b, i) end
			return s
		end,
		Lerp = function(a, b, t)
			t = R.tonumber(t) or 0
			return map2(function(x, y) return x + (y - x) * t end)(a, b)
		end,
		Abs = function(a) return map1(R.abs)(a) end,
		Floor = function(a) return map1(R.floor)(a) end,
		Ceil = function(a) return map1(R.ceil)(a) end,
		Max = map2(R.max),
		Min = map2(R.min),
		FuzzyEq = function(a, b, eps)
			eps = eps or 1e-5
			for i = 1, n do if R.abs(comp(a, i) - comp(b, i)) > eps then return false end end
			return true
		end,
		Angle = function() return 0 end,
		Cross = function(a, b)
			if n ~= 3 then return 0 end
			return new(comp(a, 2) * comp(b, 3) - comp(a, 3) * comp(b, 2),
				comp(a, 3) * comp(b, 1) - comp(a, 1) * comp(b, 3),
				comp(a, 1) * comp(b, 2) - comp(a, 2) * comp(b, 1))
		end,
	}
	mt.__index = function(t, k)
		local fk = lower[k]
		if fk then return R.rawget(t, fk) end
		if k == "Magnitude" or k == "magnitude" then return mag(t) end
		if k == "Unit" or k == "unit" then
			local m = mag(t)
			if m == 0 then return t end
			return map1(function(x) return x / m end)(t)
		end
		return methods[k]
	end
	return { new = new }
end

local V3 = make_vec("Vector3", { "X", "Y", "Z" })
local V2 = make_vec("Vector2", { "X", "Y" })
local V3i = make_vec("Vector3int16", { "X", "Y", "Z" })
local V2i = make_vec("Vector2int16", { "X", "Y" })

local Vector3_lib = {
	new = V3.new, zero = V3.new(0, 0, 0), one = V3.new(1, 1, 1),
	xAxis = V3.new(1, 0, 0), yAxis = V3.new(0, 1, 0), zAxis = V3.new(0, 0, 1),
	FromNormalId = function() return V3.new(0, 1, 0) end,
	FromAxis = function() return V3.new(0, 1, 0) end,
}
local Vector2_lib = {
	new = V2.new, zero = V2.new(0, 0), one = V2.new(1, 1), xAxis = V2.new(1, 0), yAxis = V2.new(0, 1),
}

-- Color3
local Color3_mt = {}
local function color3(r, g, b)
	local c = { R = R.tonumber(r) or 0, G = R.tonumber(g) or 0, B = R.tonumber(b) or 0 }
	kinds[c] = "Color3"
	return R.setmetatable(c, Color3_mt)
end
local function hsv_to_rgb(h, s, v)
	h = (h % 1) * 6
	local i = R.floor(h)
	local f = h - i
	local p, q, t = v * (1 - s), v * (1 - f * s), v * (1 - (1 - f) * s)
	i = i % 6
	if i == 0 then return v, t, p elseif i == 1 then return q, v, p elseif i == 2 then return p, v, t
	elseif i == 3 then return p, q, v elseif i == 4 then return t, p, v else return v, p, q end
end
local function c255(x) return R.max(0, R.min(255, R.floor(x * 255 + 0.5))) end
local Color3_methods = {
	ToHex = function(c) return R.format("%02x%02x%02x", c255(c.R), c255(c.G), c255(c.B)) end,
	ToHSV = function() return 0, 0, 1 end,
	Lerp = function(a, b, t)
		t = R.tonumber(t) or 0
		return color3(a.R + (b.R - a.R) * t, a.G + (b.G - a.G) * t, a.B + (b.B - a.B) * t)
	end,
}
Color3_mt.__index = function(_, k) return Color3_methods[k] end
Color3_mt.__tostring = function(c) return safe_tostring(c.R) .. ", " .. safe_tostring(c.G) .. ", " .. safe_tostring(c.B) end
Color3_mt.__eq = function(a, b) return a.R == b.R and a.G == b.G and a.B == b.B end
local WHITE = color3(1, 1, 1)
local Color3_lib = {
	new = color3,
	fromRGB = function(r, g, b) return color3((R.tonumber(r) or 0) / 255, (R.tonumber(g) or 0) / 255, (R.tonumber(b) or 0) / 255) end,
	fromHSV = function(h, s, v) return color3(hsv_to_rgb(R.tonumber(h) or 0, R.tonumber(s) or 0, R.tonumber(v) or 0)) end,
	fromHex = function(hex)
		hex = R.gsub(str_arg(hex), "^#", "")
		local r = R.tonumber(R.sub(hex, 1, 2), 16) or 0
		local g = R.tonumber(R.sub(hex, 3, 4), 16) or 0
		local b = R.tonumber(R.sub(hex, 5, 6), 16) or 0
		return color3(r / 255, g / 255, b / 255)
	end,
}

-- UDim / UDim2
local UDim_mt = { __tostring = function(u) return safe_tostring(u.Scale) .. ", " .. safe_tostring(u.Offset) end }
local function udim(s, o)
	local u = { Scale = R.tonumber(s) or 0, Offset = R.tonumber(o) or 0 }
	kinds[u] = "UDim"
	return R.setmetatable(u, UDim_mt)
end
local UDim2_mt = {}
local function udim2(xs, xo, ys, yo)
	local x, y
	if R.type(xs) == "table" then x, y = xs, xo else x, y = udim(xs, xo), udim(ys, yo) end
	local u = { X = x, Y = y, Width = x, Height = y }
	kinds[u] = "UDim2"
	return R.setmetatable(u, UDim2_mt)
end
UDim2_mt.__tostring = function(u) return "{" .. safe_tostring(u.X) .. "}, {" .. safe_tostring(u.Y) .. "}" end
UDim2_mt.__add = function(a, b)
	return udim2(a.X.Scale + b.X.Scale, a.X.Offset + b.X.Offset, a.Y.Scale + b.Y.Scale, a.Y.Offset + b.Y.Offset)
end
UDim2_mt.__sub = function(a, b)
	return udim2(a.X.Scale - b.X.Scale, a.X.Offset - b.X.Offset, a.Y.Scale - b.Y.Scale, a.Y.Offset - b.Y.Offset)
end
UDim2_mt.__index = function() return nil end
local UDim_lib = { new = udim }
local UDim2_lib = {
	new = udim2,
	fromScale = function(x, y) return udim2(x, 0, y, 0) end,
	fromOffset = function(x, y) return udim2(0, x, 0, y) end,
}

-- CFrame (só posição; rotações são identidade)
local CF_mt = {}
local cframe
local function xyz(v)
	if R.type(v) == "table" then
		return R.tonumber(R.rawget(v, "X")) or 0, R.tonumber(R.rawget(v, "Y")) or 0, R.tonumber(R.rawget(v, "Z")) or 0
	end
	return 0, 0, 0
end
cframe = function(x, y, z)
	x, y, z = R.tonumber(x) or 0, R.tonumber(y) or 0, R.tonumber(z) or 0
	local c = { X = x, Y = y, Z = z, Position = V3.new(x, y, z) }
	kinds[c] = "CFrame"
	return R.setmetatable(c, CF_mt)
end
CF_mt.__mul = function(a, b)
	local ax, ay, az = xyz(a)
	local bx, by, bz = xyz(b)
	if kinds[b] == "Vector3" then return V3.new(ax + bx, ay + by, az + bz) end
	return cframe(ax + bx, ay + by, az + bz)
end
CF_mt.__add = function(a, b)
	local ax, ay, az = xyz(a)
	local bx, by, bz = xyz(b)
	return cframe(ax + bx, ay + by, az + bz)
end
CF_mt.__sub = function(a, b)
	local ax, ay, az = xyz(a)
	local bx, by, bz = xyz(b)
	return cframe(ax - bx, ay - by, az - bz)
end
CF_mt.__eq = function(a, b)
	local ax, ay, az = xyz(a)
	local bx, by, bz = xyz(b)
	return ax == bx and ay == by and az == bz
end
CF_mt.__tostring = function(a)
	local x, y, z = xyz(a)
	return R.concat({ safe_tostring(x), safe_tostring(y), safe_tostring(z), "1", "0", "0", "0", "1", "0", "0", "0", "1" }, ", ")
end
local CF_methods = {
	Inverse = function(a) local x, y, z = xyz(a); return cframe(-x, -y, -z) end,
	ToWorldSpace = function(a, b) return a * b end,
	ToObjectSpace = function(a, b)
		local ax, ay, az = xyz(a)
		local bx, by, bz = xyz(b)
		return cframe(bx - ax, by - ay, bz - az)
	end,
	PointToWorldSpace = function(a, v)
		local ax, ay, az = xyz(a)
		local x, y, z = xyz(v)
		return V3.new(ax + x, ay + y, az + z)
	end,
	PointToObjectSpace = function(a, v)
		local ax, ay, az = xyz(a)
		local x, y, z = xyz(v)
		return V3.new(x - ax, y - ay, z - az)
	end,
	VectorToWorldSpace = function(_, v) return v end,
	VectorToObjectSpace = function(_, v) return v end,
	Lerp = function(a, b, t)
		t = R.tonumber(t) or 0
		local ax, ay, az = xyz(a)
		local bx, by, bz = xyz(b)
		return cframe(ax + (bx - ax) * t, ay + (by - ay) * t, az + (bz - az) * t)
	end,
	GetComponents = function(a) local x, y, z = xyz(a); return x, y, z, 1, 0, 0, 0, 1, 0, 0, 0, 1 end,
	ToEulerAnglesXYZ = function() return 0, 0, 0 end,
	ToEulerAnglesYXZ = function() return 0, 0, 0 end,
	ToOrientation = function() return 0, 0, 0 end,
	ToAxisAngle = function() return V3.new(0, 1, 0), 0 end,
	FuzzyEq = function() return true end,
	Orthonormalize = function(a) return a end,
}
CF_methods.components = CF_methods.GetComponents
CF_mt.__index = function(t, k)
	if k == "LookVector" or k == "lookVector" then return V3.new(0, 0, -1) end
	if k == "RightVector" or k == "rightVector" then return V3.new(1, 0, 0) end
	if k == "UpVector" or k == "upVector" then return V3.new(0, 1, 0) end
	if k == "Rotation" then return cframe(0, 0, 0) end
	if k == "p" then return R.rawget(t, "Position") end
	if k == "x" then return R.rawget(t, "X") end
	if k == "y" then return R.rawget(t, "Y") end
	if k == "z" then return R.rawget(t, "Z") end
	return CF_methods[k]
end
local function cf_from_first(a) local x, y, z = xyz(a); return cframe(x, y, z) end
local CFrame_lib = {
	new = function(a, b, c)
		if a == nil then return cframe(0, 0, 0) end
		if R.type(a) == "table" then return cf_from_first(a) end
		return cframe(a, b, c)
	end,
	Angles = function() return cframe(0, 0, 0) end,
	fromEulerAnglesXYZ = function() return cframe(0, 0, 0) end,
	fromEulerAnglesYXZ = function() return cframe(0, 0, 0) end,
	fromOrientation = function() return cframe(0, 0, 0) end,
	fromAxisAngle = function() return cframe(0, 0, 0) end,
	fromMatrix = cf_from_first,
	lookAt = cf_from_first,
	lookAlong = cf_from_first,
	identity = cframe(0, 0, 0),
}

-- Enum
local Enum_lib
do
	local enum_types = {}
	local item_mt = {
		__tostring = function(it) return "Enum." .. R.rawget(it, "EnumType").Name .. "." .. it.Name end,
	}
	local type_mt = {}
	type_mt.__index = function(t, k)
		if k == "GetEnumItems" then return function() return {} end end
		if R.type(k) ~= "string" then return nil end
		local items = R.rawget(t, "_items")
		local it = items[k]
		if not it then
			local cnt = R.rawget(t, "_count")
			R.rawset(t, "_count", cnt + 1)
			it = { Name = k, Value = cnt, EnumType = t }
			kinds[it] = "EnumItem"
			R.setmetatable(it, item_mt)
			items[k] = it
		end
		return it
	end
	type_mt.__tostring = function(t) return R.rawget(t, "Name") end
	local root_mt = {}
	root_mt.__index = function(_, k)
		if k == "GetEnums" then return function() return {} end end
		if R.type(k) ~= "string" then return nil end
		local et = enum_types[k]
		if not et then
			et = { Name = k, _items = {}, _count = 0 }
			kinds[et] = "Enum"
			R.setmetatable(et, type_mt)
			enum_types[k] = et
		end
		return et
	end
	root_mt.__tostring = function() return "Enum" end
	Enum_lib = R.setmetatable({}, root_mt)
	kinds[Enum_lib] = "Enums"
end

-- Random determinístico (MINSTD)
local function make_lcg(seed)
	local state = R.floor(R.tonumber(seed) or 0) % 2147483647
	if state <= 0 then state = 1 end
	return function()
		state = (state * 48271) % 2147483647
		return state / 2147483647
	end
end
local random_new
local Random_lib = {
	new = function(seed)
		local gen = make_lcg(seed or 42)
		local r = {}
		function r:NextNumber(a, b) a = a or 0; b = b or 1; return a + gen() * (b - a) end
		function r:NextInteger(a, b) a = a or 1; b = b or 100; return a + R.floor(gen() * (b - a + 1)) end
		function r:NextUnitVector() return V3.new(gen(), gen(), gen()).Unit end
		function r:Shuffle(t)
			for i = #t, 2, -1 do
				local j = 1 + R.floor(gen() * i)
				t[i], t[j] = t[j], t[i]
			end
		end
		function r:Clone() return random_new(42) end
		kinds[r] = "Random"
		return r
	end,
}
random_new = Random_lib.new

-- math / os restritos
local det_random = make_lcg(1337)
local sb_math = {}
for k, v in R.pairs(math) do sb_math[k] = v end
sb_math.random = function(a, b)
	local r = det_random()
	if a == nil then return r end
	if b == nil then return R.floor(r * a) + 1 end
	return R.floor(r * (b - a + 1)) + a
end
sb_math.randomseed = function(s) det_random = make_lcg(s) end

local sb_os = {
	clock = function() return R.clock() + vclock end,
	time = function(t)
		if t ~= nil and R.os_time then
			local ok, r = R.pcall(R.os_time, t)
			if ok then return r end
		end
		return R.floor(now())
	end,
	date = function(...)
		if R.os_date then
			local ok, r = R.pcall(R.os_date, ...)
			if ok then return r end
		end
		return ""
	end,
	difftime = function(a, b) return (R.tonumber(a) or 0) - (R.tonumber(b) or 0) end,
}

-- ---------- Instance mocks ----------
local SIGNALS = {}
for name in R.gmatch("Changed Heartbeat RenderStepped Stepped PreRender PreSimulation PostSimulation PreAnimation "
	.. "PlayerAdded PlayerRemoving CharacterAdded CharacterRemoving CharacterAppearanceLoaded InputBegan InputEnded "
	.. "InputChanged MouseButton1Click MouseButton1Down MouseButton1Up MouseButton2Click MouseEnter MouseLeave "
	.. "MouseMoved Activated Deactivated Touched TouchEnded ChildAdded ChildRemoved DescendantAdded DescendantRemoving "
	.. "OnClientEvent OnServerEvent Triggered TriggerEnded Died Completed Equipped Unequipped FocusLost Focused Event "
	.. "Idled Running Jumping StateChanged Seated AncestryChanged Destroying", "%S+") do
	SIGNALS[name] = true
end

local METHODS, PROPS = {}, {}
local QUIET = {}
for name in R.gmatch("IsA IsDescendantOf IsAncestorOf GetChildren GetDescendants GetAttribute GetAttributes "
	.. "FindFirstChild FindFirstChildOfClass FindFirstChildWhichIsA FindFirstAncestor FindFirstAncestorOfClass "
	.. "FindFirstAncestorWhichIsA WaitForChild GetFullName GetPlayers Disconnect Wait IsClient IsServer IsStudio "
	.. "IsRunning IsLoaded FireServer FireClient FireAllClients InvokeServer InvokeClient HttpGet HttpGetAsync "
	.. "HttpPost HttpPostAsync GetAsync PostAsync RequestAsync", "%S+") do
	QUIET[name] = true
end

local OBJ_CHILD_LIMIT = 500
local object_counter = 0
local obj_mt = {}
local game_obj, workspace_obj, script_obj

local function make_object(path, name, class, parent)
	object_counter = object_counter + 1
	local obj = {}
	local is_signal = SIGNALS[name] or false
	object_data[obj] = {
		path = path, name = name, class = class or name, parent = parent, props = {}, children = {},
		nchildren = 0, bound = {}, attrs = {}, id = object_counter, is_signal = is_signal, obj = obj,
	}
	kinds[obj] = is_signal and "RBXScriptSignal" or "Instance"
	return R.setmetatable(obj, obj_mt)
end

local function child(d, k)
	local c = d.children[k]
	if c then return c end
	local ks = (R.type(k) == "string") and k or safe_tostring(k)
	c = make_object(d.path .. "." .. ks, ks, ks, d.obj)
	if d.nchildren < OBJ_CHILD_LIMIT then
		d.children[k] = c
		d.nchildren = d.nchildren + 1
	end
	return c
end

local function path_obj(...)
	local o = game_obj
	for i = 1, R.select("#", ...) do o = child(object_data[o], (R.select(i, ...))) end
	return o
end

local function bind(d, k, m)
	local b = d.bound[k]
	if b then return b end
	local loud = not QUIET[k]
	b = function(self, ...)
		if loud then trace_add("call", d.path .. ":" .. k .. "(" .. fmt_args(...) .. ")") end
		return m(d, self, ...)
	end
	d.bound[k] = b
	return b
end

obj_mt.__index = function(t, k)
	local d = object_data[t]
	if d == nil or k == nil then return nil end
	local pv = d.props[k]
	if pv ~= nil then return pv end
	if R.type(k) == "string" then
		local m = METHODS[k]
		if m then return bind(d, k, m) end
		local p = PROPS[k]
		if p ~= nil then
			if R.type(p) == "function" then return p(d) end
			return p
		end
		if R.sub(k, -6) == "Color3" then return WHITE end
	end
	return child(d, k)
end

obj_mt.__newindex = function(t, k, v)
	local d = object_data[t]
	if d == nil or k == nil then return end
	d.props[k] = v
	if k == "Name" and R.type(v) == "string" then d.name = v end
	trace_add("set", d.path .. "." .. safe_tostring(k) .. " = " .. fmt_value(v))
end

obj_mt.__call = function(t, ...)
	local d = object_data[t]
	if d == nil then return nil end
	if R.select("#", ...) >= 1 and d.parent and R.rawequal((...), d.parent) then
		trace_add("call", object_data[d.parent].path .. ":" .. d.name .. "(" .. fmt_args(R.select(2, ...)) .. ")")
	else
		trace_add("call", d.path .. "(" .. fmt_args(...) .. ")")
	end
	return child(d, "()")
end

obj_mt.__tostring = function(t)
	local d = object_data[t]
	if not d then return "Instance" end
	local n = d.props.Name
	if R.type(n) == "string" then return n end
	return d.name
end
local function zero() return 0 end
local function no() return false end
obj_mt.__add, obj_mt.__sub, obj_mt.__mul, obj_mt.__div = zero, zero, zero, zero
obj_mt.__mod, obj_mt.__pow, obj_mt.__unm, obj_mt.__idiv, obj_mt.__len = zero, zero, zero, zero, zero
obj_mt.__lt, obj_mt.__le = no, no
obj_mt.__concat = function(a, b) return safe_tostring(a) .. safe_tostring(b) end
obj_mt.__iter = function() return R.next, {} end
obj_mt.__metatable = "The metatable is locked"

-- raízes
game_obj = make_object("game", "Game", "DataModel", nil)
workspace_obj = make_object("workspace", "Workspace", "Workspace", game_obj)
script_obj = make_object("script", "Script", "LocalScript", nil)
object_data[script_obj].is_script_root = true
do
	local gd = object_data[game_obj]
	gd.children.Workspace = workspace_obj
	gd.children.workspace = workspace_obj
	gd.nchildren = 2
end

-- propriedades por defeito
PROPS.Name = function(d) return d.name end
PROPS.ClassName = function(d) return d.class end
PROPS.className = PROPS.ClassName
PROPS.Parent = function(d)
	if d.parent then return d.parent end
	if d.is_script_root then return child(d, "Parent") end
	return nil
end
PROPS.Position = V3.new(0, 5, 0)
PROPS.Origin = V3.new(0, 5, 0)
PROPS.Target = V3.new(0, 5, 0)
PROPS.Size = V3.new(1, 1, 1)
PROPS.Velocity = V3.new(0, 0, 0)
PROPS.AssemblyLinearVelocity = V3.new(0, 0, 0)
PROPS.Normal = V3.new(0, 1, 0)
PROPS.AbsoluteSize = V2.new(1920, 1080)
PROPS.ViewportSize = V2.new(1920, 1080)
PROPS.AbsolutePosition = V2.new(0, 0)
PROPS.CFrame = cframe(0, 5, 0)
PROPS.LookVector = V3.new(0, 0, -1)
PROPS.RightVector = V3.new(1, 0, 0)
PROPS.UpVector = V3.new(0, 1, 0)
PROPS.Unit = V3.new(0, 0, 1)
PROPS.Color = WHITE
PROPS.UnixTimestamp = function() return R.floor(now()) end
PROPS.UnixTimestampMillis = function() return R.floor(now() * 1000) end
for name in R.gmatch("Visible Enabled Anchored CanCollide Active Archivable Selectable Connected", "%S+") do PROPS[name] = true end
for name in R.gmatch("Playing IsPlaying Looped Disabled Locked Sit PlatformStand", "%S+") do PROPS[name] = false end
local NUMS = {
	Value = 0, Magnitude = 0, X = 0, Y = 0, Z = 0, W = 0, Health = 100, MaxHealth = 100, WalkSpeed = 16,
	JumpPower = 50, JumpHeight = 7.2, HipHeight = 2, UserId = 1, AccountAge = 1000, FieldOfView = 70,
	Transparency = 0, Volume = 0.5, TimePosition = 0, TimeLength = 1, Speed = 1, Brightness = 1, ClockTime = 12,
	Gravity = 196.2, PlaceId = 1, GameId = 1, PlaceVersion = 1, CreatorId = 1, ZIndex = 1, LayoutOrder = 0,
	Rotation = 0, Duration = 1,
}
for k, v in R.pairs(NUMS) do PROPS[k] = v end
PROPS.Text = ""
PROPS.PlaceholderText = ""
PROPS.DisplayName = "Player"
PROPS.TimeOfDay = "12:00:00"
PROPS.JobId = "00000000-0000-0000-0000-000000000000"

-- ---------- métodos ----------
local callbacks, conn_counter = {}, 0

local function noop() end
local function def_list(names, fn)
	for name in R.gmatch(names, "%S+") do METHODS[name] = fn end
end
def_list("Destroy ClearAllChildren Remove Play Pause Stop Cancel Resume UnbindFromRenderStep BindAction UnbindAction "
	.. "PreloadAsync AddItem PlayLocalSound MoveTo ChangeState TakeDamage EquipTool UnequipTools SetNetworkOwner "
	.. "SetPrimaryPartCFrame PivotTo TranslateBy BreakJoints MakeJoints Resize SetCore SetCoreGuiEnabled Emit Fire "
	.. "Reset LoadCharacter PromptPurchase PromptGamePassPurchase PromptProductPurchase", noop)
def_list("GetTouchingParts GetConnectedParts GetPlayingAnimationTracks GetTagged GetPartBoundsInBox GetPartBoundsInRadius "
	.. "GetPartsInPart FindPartsInRegion3 GetEnumItems GetJoints GetKeysPressed GetMouseButtonsPressed GetFriendsOnline "
	.. "GetTags GetChildren GetDescendants", function() return {} end)
def_list("UserOwnsGamePassAsync PlayerOwnsAsset IsKeyDown IsMouseButtonPressed IsStudio IsServer HasTag IsInGroup "
	.. "IsFriendsWith IsRunMode CanSetNetworkOwnership", function() return false end)
def_list("IsA IsDescendantOf IsAncestorOf IsClient IsLoaded IsRunning", function() return true end)
def_list("GetFocusedTextBox GetNetworkOwner", function() return nil end)

METHODS.GetService = function(_, _, name) return child(object_data[game_obj], str_arg(name)) end
METHODS.FindFirstChild = function(d, _, name)
	if name == nil then return nil end
	return child(d, str_arg(name))
end
METHODS.WaitForChild = METHODS.FindFirstChild
def_list("FindFirstChildOfClass FindFirstChildWhichIsA", function(d, _, cls) return child(d, str_arg(cls)) end)
def_list("FindFirstAncestor FindFirstAncestorOfClass FindFirstAncestorWhichIsA", function(d) return d.parent or game_obj end)
METHODS.GetFullName = function(d) return d.path end
METHODS.Clone = function(d)
	local c = make_object(d.path .. "#clone", d.name, d.class, nil)
	for k, v in R.pairs(d.props) do object_data[c].props[k] = v end
	return c
end
METHODS.GetAttribute = function(d, _, name) return d.attrs[name] end
METHODS.SetAttribute = function(d, _, name, v) d.attrs[name] = v end
METHODS.GetAttributes = function(d)
	local r = {}
	for k, v in R.pairs(d.attrs) do r[k] = v end
	return r
end
local function signal_child(d, label)
	local c = child(d, "Changed(" .. label .. ")")
	object_data[c].is_signal = true
	object_data[c].name = "Changed"
	return c
end
METHODS.GetPropertyChangedSignal = function(d, _, prop) return signal_child(d, str_arg(prop)) end
METHODS.GetAttributeChangedSignal = function(d, _, prop) return signal_child(d, "attr:" .. str_arg(prop)) end

local function local_player() return path_obj("Players", "LocalPlayer") end
METHODS.GetPlayers = function() return { local_player() } end
METHODS.GetPlayerFromCharacter = local_player
METHODS.GetPlayerByUserId = local_player
METHODS.GetNameFromUserIdAsync = function() return "Player" end
METHODS.GetUserIdFromNameAsync = function() return 1 end
METHODS.GetRankInGroup = function() return 0 end
METHODS.GetMouseLocation = function() return V2.new(0, 0) end
METHODS.GetServerTimeNow = function() return now() end
METHODS.GetMass = function() return 1 end
METHODS.Raycast = function(d) return child(d, "RaycastResult") end
METHODS.GetProductInfo = function()
	return {
		Name = "MockProduct", Description = "", PriceInRobux = 0, ProductId = 1, AssetId = 1, IsForSale = false,
		Creator = { Name = "Mock", Id = 1, CreatorTargetId = 1, CreatorType = "User" },
	}
end

METHODS.Connect = function(d, _, fn)
	conn_counter = conn_counter + 1
	if R.type(fn) == "function" and #callbacks < 400 then
		callbacks[#callbacks + 1] = { signal = d.name, path = d.path, fn = fn }
	end
	local c = make_object(d.path .. ":Connect#" .. conn_counter, "RBXScriptConnection", "RBXScriptConnection", nil)
	object_data[c].props.Connected = true
	return c
end
METHODS.ConnectParallel = METHODS.Connect
METHODS.Once = METHODS.Connect
METHODS.Disconnect = function(d) d.props.Connected = false end
METHODS.BindToRenderStep = function(d, _, _, _, fn)
	if R.type(fn) == "function" and #callbacks < 400 then
		callbacks[#callbacks + 1] = { signal = "RenderStepped", path = d.path .. ":BindToRenderStep", fn = fn }
	end
end

local function remote_event(kind)
	return function(d, _, ...)
		counters.remotes = counters.remotes + 1
		event("remote", d.path .. ":" .. kind .. "(" .. fmt_args(...) .. ")")
		if kind == "InvokeServer" or kind == "InvokeClient" then return child(d, "InvokeResult") end
	end
end
for _, kind in R.ipairs({ "FireServer", "FireClient", "FireAllClients", "InvokeServer", "InvokeClient" }) do
	METHODS[kind] = remote_event(kind)
end
METHODS.Kick = function(_, _, reason) event("kick", fmt_value(reason)) end
def_list("Teleport TeleportToPlaceInstance TeleportAsync", function(d, _, ...)
	event("teleport", d.path .. ":Teleport(" .. fmt_args(...) .. ")")
end)

-- rede
local function is_webhook(u) return R.find(u, "api/webhooks/") ~= nil end
local function net_record(method, url, body, headers)
	counters.requests = counters.requests + 1
	local u = str_arg(url)
	local text = str_arg(method) .. " " .. clip(u, 1000)
	if body ~= nil then text = text .. " body=" .. quote(clip(str_arg(body), 2000)) end
	if R.type(headers) == "table" then text = text .. " headers=" .. fmt_value(headers) end
	event("http", text)
	if is_webhook(u) then event("webhook", clip(u, 1000)) end
end
local function http_response() return { Success = true, StatusCode = 200, StatusMessage = "OK", Headers = {}, Body = "{}" } end
local function request_impl(opts)
	if R.type(opts) == "table" then
		net_record(opts.Method or "GET", opts.Url or opts.URL or "", opts.Body, opts.Headers)
	else
		net_record("GET", opts)
	end
	return http_response()
end
def_list("HttpGet HttpGetAsync GetAsync", function(_, _, url)
	net_record("GET", url)
	return "-- [envlog2] HttpGet stub for " .. clip(str_arg(url), 200) .. "\nreturn nil"
end)
def_list("HttpPost HttpPostAsync PostAsync", function(_, _, url, data)
	net_record("POST", url, data)
	return "{}"
end)
METHODS.RequestAsync = function(_, _, opts) return request_impl(opts) end

-- JSON / base64
local json_encode, json_decode
json_encode = function(v, depth)
	depth = depth or 0
	local t = R.type(v)
	if t == "nil" then return "null" end
	if t == "boolean" then return R.tostring(v) end
	if t == "number" then
		if v ~= v or v == R.huge or v == -R.huge then return "null" end
		return safe_tostring(v)
	end
	if t == "string" then
		return '"' .. R.gsub(v, '[%c"\\]', function(c) return ESC[c] or R.format("\\u%04x", R.byte(c)) end) .. '"'
	end
	if t == "table" and depth < 10 and not kinds[v] and not object_data[v] then
		local n = 0
		for _ in R.pairs(v) do n = n + 1 end
		local parts = {}
		if n == #v then
			for i = 1, n do parts[i] = json_encode(v[i], depth + 1) end
			return "[" .. R.concat(parts, ",") .. "]"
		end
		for k, val in R.pairs(v) do parts[#parts + 1] = json_encode(safe_tostring(k), depth + 1) .. ":" .. json_encode(val, depth + 1) end
		return "{" .. R.concat(parts, ",") .. "}"
	end
	return "null"
end
json_decode = function(s)
	local pos = 1
	local value
	local function ws() pos = R.find(s, "[^ \n\r\t]", pos) or (#s + 1) end
	local function str()
		local out, i = {}, pos + 1
		while true do
			local c = R.sub(s, i, i)
			if c == "" then R.error("unterminated string", 0) end
			if c == '"' then pos = i + 1; return R.concat(out) end
			if c == "\\" then
				local n = R.sub(s, i + 1, i + 1)
				if n == "u" then
					local cp = R.tonumber(R.sub(s, i + 2, i + 5), 16) or 63
					out[#out + 1] = (utf8 and utf8.char) and utf8.char(cp) or R.char(cp % 256)
					i = i + 6
				else
					out[#out + 1] = ({ n = "\n", t = "\t", r = "\r", b = "\b", f = "\f" })[n] or n
					i = i + 2
				end
			else
				out[#out + 1] = c
				i = i + 1
			end
		end
	end
	value = function()
		ws()
		local c = R.sub(s, pos, pos)
		if c == "{" then
			local o = {}
			pos = pos + 1
			ws()
			if R.sub(s, pos, pos) == "}" then pos = pos + 1; return o end
			while true do
				ws()
				local k = str()
				ws()
				pos = pos + 1
				o[k] = value()
				ws()
				local d = R.sub(s, pos, pos)
				pos = pos + 1
				if d == "}" then return o end
				if d ~= "," then R.error("bad json object", 0) end
			end
		elseif c == "[" then
			local a, i = {}, 0
			pos = pos + 1
			ws()
			if R.sub(s, pos, pos) == "]" then pos = pos + 1; return a end
			while true do
				i = i + 1
				a[i] = value()
				ws()
				local d = R.sub(s, pos, pos)
				pos = pos + 1
				if d == "]" then return a end
				if d ~= "," then R.error("bad json array", 0) end
			end
		elseif c == '"' then
			return str()
		elseif R.sub(s, pos, pos + 3) == "true" then pos = pos + 4; return true
		elseif R.sub(s, pos, pos + 4) == "false" then pos = pos + 5; return false
		elseif R.sub(s, pos, pos + 3) == "null" then pos = pos + 4; return nil
		end
		local num = R.match(s, "^-?%d+%.?%d*[eE]?[+-]?%d*", pos)
		if not num or num == "" then R.error("bad json", 0) end
		pos = pos + #num
		return R.tonumber(num)
	end
	return value()
end
METHODS.JSONEncode = function(_, _, v) return json_encode(v) end
METHODS.JSONDecode = function(_, _, s)
	local ok, r = R.pcall(json_decode, str_arg(s))
	if ok then return r end
	R.error("Can't parse JSON", 0)
end

local b64encode, b64decode
do
	local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	local DEC = {}
	for i = 1, 64 do DEC[R.byte(B64, i)] = i - 1 end
	b64encode = function(s)
		s = str_arg(s)
		local out = {}
		for i = 1, #s, 3 do
			local a, b, c = R.byte(s, i, i + 2)
			local n = a * 65536 + (b or 0) * 256 + (c or 0)
			local c1, c2 = R.floor(n / 262144) % 64, R.floor(n / 4096) % 64
			local c3, c4 = R.floor(n / 64) % 64, n % 64
			out[#out + 1] = R.sub(B64, c1 + 1, c1 + 1) .. R.sub(B64, c2 + 1, c2 + 1)
				.. (b and R.sub(B64, c3 + 1, c3 + 1) or "=") .. (c and R.sub(B64, c4 + 1, c4 + 1) or "=")
		end
		return R.concat(out)
	end
	b64decode = function(s)
		s = (R.gsub(str_arg(s), "[^%w%+/]", ""))
		local out = {}
		for i = 1, #s, 4 do
			local a, b, c, d = R.byte(s, i, i + 3)
			local n = (DEC[a] or 0) * 262144 + (DEC[b] or 0) * 4096 + (c and (DEC[c] or 0) or 0) * 64 + (d and (DEC[d] or 0) or 0)
			local nbytes = (d and 3) or (c and 2) or 1
			out[#out + 1] = R.sub(R.char(R.floor(n / 65536) % 256, R.floor(n / 256) % 256, n % 256), 1, nbytes)
		end
		return R.concat(out)
	end
end

-- Instance.new
local instance_counter = 0
local Instance_lib = {
	new = function(class, parent)
		class = str_arg(class)
		instance_counter = instance_counter + 1
		instances_created[class] = (instances_created[class] or 0) + 1
		trace_add("new", "Instance.new(" .. quote(clip(class, 100)) .. (parent ~= nil and (", " .. fmt_value(parent)) or "") .. ")")
		local o = make_object(class .. "#" .. instance_counter, class, class, nil)
		if parent ~= nil then object_data[o].props.Parent = parent end
		return o
	end,
	fromExisting = function(o) return o end,
}

local function ctor_stub(name)
	return R.setmetatable({}, {
		__index = function(_, k)
			return function(...)
				instance_counter = instance_counter + 1
				local o = make_object("<" .. name .. "." .. safe_tostring(k) .. "#" .. instance_counter .. ">", name, name, nil)
				kinds[o] = name
				return o
			end
		end,
	})
end

-- ---------- sandbox ----------
local sandbox = {}
sandbox.pcall, sandbox.xpcall, sandbox.select = R.pcall, R.xpcall, R.select
sandbox.tostring, sandbox.tonumber = R.tostring, R.tonumber
sandbox.pairs, sandbox.ipairs, sandbox.next = R.pairs, R.ipairs, R.next
sandbox.rawget, sandbox.rawset, sandbox.rawequal = R.rawget, R.rawset, R.rawequal
sandbox.setmetatable, sandbox.getmetatable = R.setmetatable, R.getmetatable
sandbox.assert, sandbox.rawlen, sandbox.collectgarbage = assert, rawlen, collectgarbage
sandbox.coroutine, sandbox.string, sandbox.table = coroutine, string, table
sandbox.utf8, sandbox.buffer = utf8, buffer
sandbox.unpack = R.unpack
sandbox.math = sb_math
sandbox.os = sb_os
sandbox.bit32 = bit32_impl
sandbox.bit = bit_impl
sandbox._G = sandbox
sandbox.shared = {}
sandbox._VERSION = _VERSION

sandbox.type = function(v)
	if R.type(v) == "table" and kinds[v] then return "userdata" end
	return R.type(v)
end
sandbox.typeof = function(v)
	if R.type(v) == "table" then
		local k = kinds[v]
		if k then return k end
	end
	return R.typeof(v)
end

sandbox.print = function(...) record(prints, ...) end
sandbox.warn = function(...) record(warns, ...) end
sandbox.error = function(msg, level)
	note_soft(safe_tostring(msg))
	if level == 0 then R.error(msg, 0) end
	R.error(msg, (R.tonumber(level) or 1) + 1)
end
sandbox.require = function(target)
	event("require", fmt_value(target))
	instance_counter = instance_counter + 1
	return make_object("require<" .. clip(safe_tostring(target), 60) .. ">", "Module", "ModuleScript", nil)
end

-- loader
local luau_mod
do
	local ok, m = R.pcall(R.require, "@lune/luau")
	if ok and R.type(m) == "table" and m.load then luau_mod = m end
end
local function compile(src, name)
	local fn, err
	if R.loadstring then
		fn, err = R.loadstring(src, name)
		if fn then
			local ok = R.setfenv and R.pcall(R.setfenv, fn, sandbox)
			env_mode = ok and "loadstring+setfenv" or "loadstring (sem setfenv)"
		end
	elseif luau_mod then
		local ok, res = R.pcall(luau_mod.load, src, { debugName = name, environment = sandbox, injectGlobals = false })
		if ok then
			fn = res
			local sok = R.setfenv and R.pcall(R.setfenv, fn, sandbox)
			env_mode = sok and "lune luau.load+setfenv" or "lune luau.load (env copiado)"
		else
			err = res
		end
	elseif R.load then
		fn, err = R.load(src, name, "t", sandbox)
		env_mode = "load(env)"
	else
		return nil, "no loader available"
	end
	return fn, err
end

sandbox.loadstring = function(code, chunkname)
	if R.type(code) ~= "string" then
		return nil, "bad argument #1 to 'loadstring' (string expected, got " .. R.type(code) .. ")"
	end
	if R.sub(code, 1, 20) == "-- [envlog2] HttpGet" then
		return compile(code, "=http_stub")
	end
	counters.loads = counters.loads + 1
	local idx = capture_source(code, R.type(chunkname) == "string" and chunkname or nil)
	if not idx then return nil, "envlog2: too many loadstring calls" end
	local rec = loads[idx]
	rec.count = rec.count + 1
	if rec.count > 50 then return nil, "envlog2: load recursion guard" end
	local fn, err = compile(code, R.type(chunkname) == "string" and chunkname or ("=loadstring_" .. idx))
	if not fn then
		rec.err = safe_tostring(err)
		return nil, err
	end
	return fn
end
sandbox.load = function(chunk, name)
	if R.type(chunk) == "function" then
		local parts = {}
		while true do
			local piece = chunk()
			if piece == nil or piece == "" then break end
			parts[#parts + 1] = piece
		end
		chunk = R.concat(parts)
	end
	return sandbox.loadstring(chunk, name)
end
sandbox.getfenv = function() return sandbox end
sandbox.setfenv = function(f) return f end
sandbox.getgenv = function() return sandbox end
sandbox.getrenv = function() return sandbox end
sandbox.newproxy = R.newproxy or function() return R.setmetatable({}, {}) end

-- scheduler com tempo virtual
local threads, scheduled = {}, {}
local fired_upto = 0
local main_error, main_traceback, main_returns = nil, nil, nil
local sb_wait

local function resume_item(item)
	local co = item.co
	if R.status(co) ~= "suspended" then return end
	if counters.resumes >= CONFIG.MAX_RESUMES then
		abort_reason = abort_reason or "max thread resumes reached"
		return
	end
	counters.resumes = counters.resumes + 1
	local r
	if item.args then
		local a, n = item.args, item.n
		item.args = nil
		r = { R.resume(co, R.unpack(a, 1, n)) }
	else
		r = { R.resume(co) }
	end
	if not r[1] then
		local msg = safe_tostring(r[2])
		local tb = ""
		if R.debug and R.debug.traceback then
			local tok, t = R.pcall(R.debug.traceback, co, msg)
			if tok and R.type(t) == "string" then tb = t end
		end
		scheduled[co] = nil
		if item.main then
			main_error, main_traceback = msg, tb
			errors_list[#errors_list + 1] = clip("runtime: " .. msg, 4000)
			if tb ~= "" then errors_list[#errors_list + 1] = clip("traceback: " .. tb, 4000) end
		else
			errors_list[#errors_list + 1] = clip("thread error: " .. msg, 4000)
		end
	elseif R.status(co) == "dead" then
		scheduled[co] = nil
		if item.main then main_returns = r end
	else
		item.wake = vclock + (R.tonumber(r[2]) or 0)
		threads[#threads + 1] = item
	end
end

local function spawn_thread(fn, wake, ...)
	counters.threads = counters.threads + 1
	local co = R.create(fn)
	scheduled[co] = true
	local item = { co = co, wake = wake, args = { ... }, n = R.select("#", ...) }
	if wake <= vclock then resume_item(item) else threads[#threads + 1] = item end
	return co
end

sb_wait = function(t)
	t = R.tonumber(t) or 0.03
	if t < 0.001 then t = 0.001 end
	counters.waits = counters.waits + 1
	if counters.waits > CONFIG.MAX_WAITS then
		abort_reason = abort_reason or "wait budget exceeded (loop infinito?)"
		R.error("envlog2: execution budget exceeded", 0)
	end
	if vclock + t > CONFIG.MAX_VIRTUAL_TIME then
		abort_reason = abort_reason or ("virtual time limit (" .. CONFIG.MAX_VIRTUAL_TIME .. "s) reached")
		R.error("envlog2: virtual time limit reached", 0)
	end
	local co = R.running()
	if co and scheduled[co] then R.yield(t) else vclock = vclock + t end
	return t
end
METHODS.Wait = function(d)
	sb_wait(0.03)
	return child(d, "Wait()")
end

sandbox.task = {
	wait = sb_wait,
	spawn = function(f, ...)
		if R.type(f) == "function" then return spawn_thread(f, vclock, ...) end
		if R.type(f) == "thread" then
			scheduled[f] = true
			resume_item({ co = f, args = { ... }, n = R.select("#", ...) })
			return f
		end
	end,
	defer = function(f, ...) if R.type(f) == "function" then return spawn_thread(f, vclock + 0.001, ...) end end,
	delay = function(t, f, ...)
		if R.type(f) == "function" then return spawn_thread(f, vclock + R.max(R.tonumber(t) or 0, 0.001), ...) end
	end,
	cancel = function(co)
		for i = #threads, 1, -1 do
			if threads[i].co == co then R.remove(threads, i) end
		end
		scheduled[co] = nil
	end,
	synchronize = noop,
	desynchronize = noop,
}
sandbox.wait = function(t) local dt = sb_wait(t); return dt, now() end
sandbox.Wait = sandbox.wait
sandbox.spawn = function(f, ...) if R.type(f) == "function" then return spawn_thread(f, vclock + 0.03, ...) end end
sandbox.Spawn = sandbox.spawn
sandbox.delay = function(t, f, ...)
	if R.type(f) == "function" then return spawn_thread(f, vclock + R.max(R.tonumber(t) or 0, 0.03), ...) end
end
sandbox.Delay = sandbox.delay
sandbox.tick = function() return now() end
sandbox.time = function() return vclock end
sandbox.elapsedTime = sandbox.time
sandbox.ElapsedTime = sandbox.time
sandbox.version = function() return "0.600.0.0" end
sandbox.Version = sandbox.version
sandbox.printidentity = noop

-- disparar callbacks de sinais (Heartbeat, PlayerAdded, ...)
local TICK_SIGNALS = {}
for name in R.gmatch("Heartbeat RenderStepped Stepped PreRender PreSimulation PostSimulation PreAnimation", "%S+") do
	TICK_SIGNALS[name] = true
end
local function fire_one(cb)
	local sig = cb.signal
	local arg1
	local ticking = false
	if TICK_SIGNALS[sig] then
		ticking = true
	elseif sig == "PlayerAdded" then
		arg1 = path_obj("Players", "LocalPlayer")
	elseif sig == "CharacterAdded" then
		arg1 = path_obj("Players", "LocalPlayer", "Character")
	elseif sig == "Completed" then
		arg1 = Enum_lib.PlaybackState.Completed
	elseif CONFIG.FIRE_ALL_SIGNALS then
		arg1 = child(object_data[game_obj], "event_arg")
	else
		return
	end
	spawn_thread(function()
		if ticking then
			for _ = 1, CONFIG.TICKS do
				local ok, err
				if sig == "Stepped" then ok, err = R.pcall(cb.fn, vclock, 0.016) else ok, err = R.pcall(cb.fn, 0.016) end
				if not ok then note_soft("callback " .. cb.path .. ": " .. safe_tostring(err)); break end
				sb_wait(0.016)
			end
		else
			local ok, err = R.pcall(cb.fn, arg1)
			if not ok then note_soft("callback " .. cb.path .. ": " .. safe_tostring(err)) end
		end
	end, vclock + 0.001)
end

local function run_scheduler()
	while counters.resumes < CONFIG.MAX_RESUMES do
		while fired_upto < #callbacks and fired_upto < 400 do
			fired_upto = fired_upto + 1
			fire_one(callbacks[fired_upto])
		end
		local n = #threads
		if n == 0 then break end
		local bi, bw = 1, threads[1].wake
		for i = 2, n do
			if threads[i].wake < bw then bi, bw = i, threads[i].wake end
		end
		local item = R.remove(threads, bi)
		if bw > CONFIG.MAX_VIRTUAL_TIME then
			abort_reason = abort_reason or ("virtual time limit (" .. CONFIG.MAX_VIRTUAL_TIME .. "s) reached")
			break
		end
		if bw > vclock then vclock = bw end
		resume_item(item)
	end
	if counters.resumes >= CONFIG.MAX_RESUMES then abort_reason = abort_reason or "max thread resumes reached" end
end

-- globais Roblox
sandbox.game = game_obj
sandbox.Game = game_obj
sandbox.workspace = workspace_obj
sandbox.Workspace = workspace_obj
sandbox.script = script_obj
sandbox.Instance = Instance_lib
sandbox.Vector3 = Vector3_lib
sandbox.Vector2 = Vector2_lib
sandbox.Vector3int16 = { new = V3i.new }
sandbox.Vector2int16 = { new = V2i.new }
sandbox.CFrame = CFrame_lib
sandbox.Color3 = Color3_lib
sandbox.UDim = UDim_lib
sandbox.UDim2 = UDim2_lib
sandbox.Enum = Enum_lib
sandbox.Random = Random_lib
for name in R.gmatch("BrickColor Rect Region3 Region3int16 Ray NumberRange NumberSequence NumberSequenceKeypoint "
	.. "ColorSequence ColorSequenceKeypoint PhysicalProperties Font RaycastParams OverlapParams PathWaypoint Faces Axes "
	.. "CatalogSearchParams DateTime TweenInfo SharedTable Path2DControlPoint DockWidgetPluginGuiInfo "
	.. "SecurityCapabilities RotationCurveKey FloatCurveKey Secret Content TextChatMessageProperties", "%S+") do
	sandbox[name] = ctor_stub(name)
end
sandbox.settings = function() return make_object("settings()", "Settings", "GlobalSettings", nil) end
sandbox.UserSettings = function() return make_object("UserSettings()", "UserSettings", "UserSettings", nil) end

sandbox.debug = {
	traceback = (R.debug and R.debug.traceback) or function() return "" end,
	info = (R.debug and R.debug.info) or function() return nil end,
	getinfo = function() return { source = "=", short_src = "envlog2", what = "Lua", name = "?", namewhat = "", currentline = 0, nups = 0, nparams = 0, isvararg = false, func = noop } end,
	getupvalue = function() return nil end, setupvalue = function() return nil end,
	getlocal = function() return nil end, setlocal = function() return nil end,
	sethook = noop, gethook = function() return nil end,
	profilebegin = noop, profileend = noop,
	getmetatable = R.getmetatable, setmetatable = R.setmetatable,
	getregistry = function() return {} end,
}

-- funções de exploit / executor
do
	local function def(name, fn) sandbox[name] = fn end
	local function ret(v) return function() return v end end
	for name in R.gmatch("rconsoleclear rconsolecreate rconsoledestroy rconsolename setfflag setfpscap setsimulationradius "
		.. "sethiddenproperty saveinstance setwindowactive setwindowtitle protectgui mouse1click mouse1press mouse1release "
		.. "mouse2click mouse2press mouse2release mousemoverel mousemoveabs mousescroll keypress keyrelease keyclick "
		.. "firesignal fireclickdetector fireproximityprompt firetouchinterest setthreadidentity setidentity "
		.. "setthreadcontext setproto setconstant setstack setupvalue restorefunction cleardrawcache setnamecallmethod "
		.. "setscriptable clear_teleport_queue", "%S+") do def(name, noop) end
	for name in R.gmatch("rconsoleprint rconsoleinfo rconsolewarn rconsoleerr printconsole", "%S+") do
		def(name, function(...) record(prints, "[console]", ...) end)
	end
	for name in R.gmatch("getgc getinstances getnilinstances getconnections getscripts getrunningscripts "
		.. "getloadedmodules getconstants getupvalues getprotos getreg getsenv getcallbackvalue", "%S+") do
		def(name, function() return {} end)
	end
	for name in R.gmatch("getthreadidentity getidentity getthreadcontext", "%S+") do def(name, ret(7)) end
	for name in R.gmatch("checkcaller isnetworkowner isrbxactive iswindowactive isgameactive iswindowactive", "%S+") do
		def(name, ret(true))
	end
	for name in R.gmatch("iscclosure isreadonly isexecutorclosure is_synapse_function", "%S+") do def(name, ret(false)) end
	for name in R.gmatch("newcclosure clonefunction replaceclosure make_writeable make_readonly setreadonly "
		.. "secure_call create_secure_function", "%S+") do
		def(name, function(f) return f end)
	end
	def("islclosure", function(f) return R.type(f) == "function" end)
	def("hookfunction", function(f, g)
		trace_add("call", "hookfunction(" .. fmt_args(f, g) .. ")")
		return f
	end)
	def("hookmetamethod", function(obj, method, f)
		event("hookmetamethod", fmt_value(obj) .. ", " .. fmt_value(method))
		return function() end
	end)
	def("getnamecallmethod", ret(""))
	def("getrawmetatable", function()
		return { __index = noop, __newindex = noop, __namecall = noop, __tostring = noop, __eq = noop }
	end)
	def("getcallingscript", function() return script_obj end)
	def("getfpscap", ret(60))
	def("getfflag", ret(""))
	def("gethiddenproperty", ret(nil))
	def("getspecialinfo", function() return {} end)
	def("decompile", ret("-- decompiled"))
	def("getscriptbytecode", ret(""))
	def("getscripthash", ret(""))
	def("lz4compress", function(s) return s end)
	def("lz4decompress", function(s) return s end)
	def("MessageBox", ret(1))
	def("isvalidinstance", function(i) return i ~= nil end)
	def("validcheck", function(i) return i ~= nil end)
	def("gethui", function() return child(object_data[game_obj], "HiddenUI") end)
	def("gethiddenui", sandbox.gethui)
	def("identifyexecutor", function() return CONFIG.EXECUTOR_NAME, CONFIG.EXECUTOR_VERSION end)
	def("getexecutorname", function() return CONFIG.EXECUTOR_NAME end)
	def("gethwid", ret("HWID-MOCK"))
	def("getcustomasset", function(f) return "rbxasset://" .. str_arg(f) end)
	def("getsynasset", sandbox.getcustomasset)
	def("setclipboard", function(s) event("clipboard", quote(clip(str_arg(s), 2000))) end)
	def("toclipboard", sandbox.setclipboard)
	def("getclipboard", ret(""))
	def("queue_on_teleport", function(code)
		code = str_arg(code)
		capture_source(code, "queue_on_teleport")
		event("queue_on_teleport", quote(clip(code, 500)))
	end)
	def("queueonteleport", sandbox.queue_on_teleport)

	-- rede
	def("request", request_impl)
	def("http_request", request_impl)
	sandbox.syn = { request = request_impl, protect_gui = noop, queue_on_teleport = sandbox.queue_on_teleport }
	sandbox.http = { request = request_impl }
	sandbox.fluxus = { request = request_impl }
	sandbox.WebSocket = {
		connect = function(url)
			event("websocket", clip(str_arg(url), 1000))
			instance_counter = instance_counter + 1
			return make_object("WebSocket#" .. instance_counter, "WebSocket", "WebSocket", nil)
		end,
	}

	-- ficheiros em memória
	def("writefile", function(path, data)
		path = str_arg(path)
		data = str_arg(data)
		fake_fs[path] = data
		counters.files = counters.files + 1
		event("writefile", quote(clip(path, 200)) .. " (" .. #data .. " bytes): " .. quote(clip(data, 1500)))
	end)
	def("appendfile", function(path, data)
		path = str_arg(path)
		fake_fs[path] = (fake_fs[path] or "") .. str_arg(data)
		counters.files = counters.files + 1
		event("appendfile", quote(clip(path, 200)) .. ": " .. quote(clip(str_arg(data), 1500)))
	end)
	def("readfile", function(path)
		path = str_arg(path)
		if fake_fs[path] == nil then R.error(path .. " does not exist", 2) end
		return fake_fs[path]
	end)
	def("isfile", function(path) return fake_fs[str_arg(path)] ~= nil end)
	def("isfolder", ret(false))
	def("makefolder", noop)
	def("delfolder", noop)
	def("delfile", function(path) fake_fs[str_arg(path)] = nil end)
	def("listfiles", function() return {} end)
	def("loadfile", function(path)
		local src = fake_fs[str_arg(path)]
		if src == nil then return nil, "file not found" end
		return sandbox.loadstring(src, "=" .. str_arg(path))
	end)
	def("dofile", function(path)
		local fn, err = sandbox.loadfile(path)
		if not fn then R.error(err, 2) end
		return fn()
	end)

	-- base64 / crypt
	for name in R.gmatch("base64_encode base64encode", "%S+") do def(name, b64encode) end
	for name in R.gmatch("base64_decode base64decode", "%S+") do def(name, b64decode) end
	sandbox.crypt = {
		base64encode = b64encode, base64decode = b64decode, base64_encode = b64encode, base64_decode = b64decode,
		encrypt = function(s) return s end, decrypt = function(s) return s end,
		hash = function(s) return hash32(str_arg(s)) end,
		generatekey = function(n) return b64encode(R.rep("k", n or 32)) end,
		generatebytes = function(n) return R.rep("\0", n or 16) end,
	}
	sandbox.crypt.base64 = { encode = b64encode, decode = b64decode }

	-- Drawing
	sandbox.Drawing = {
		new = function(kind)
			instance_counter = instance_counter + 1
			return make_object("Drawing_" .. str_arg(kind) .. "#" .. instance_counter, str_arg(kind), "Drawing", nil)
		end,
		Fonts = child(object_data[game_obj], "DrawingFonts"),
	}
end

-- ---------- captura de strings descodificadas + orçamento de CPU ----------
local cpu_start = R.clock()
local captured, captured_set = {}, {}

local function check_budget()
	if R.clock() - cpu_start > CONFIG.MAX_CPU_SECONDS then
		abort_reason = abort_reason or ("cpu budget (" .. CONFIG.MAX_CPU_SECONDS .. "s) exceeded")
		R.error("envlog: cpu budget exceeded", 0)
	end
end

local function looks_useful(s)
	local n = #s
	if n < CONFIG.MIN_STRING_LEN or n > 4000 then return false end
	local bad = R.gsub(s, "[%w%p ]", "")
	return #bad <= n * 0.1
end

local INTERESTING = { "https?://", "discord%.com", "webhook", "loadstring", "HttpGet", "GetService",
	"%.lua", "pastebin", "raw%.githubusercontent", "api/webhooks" }

local function capture_string(s, how)
	if R.type(s) ~= "string" or captured_set[s] then return end
	if #captured >= CONFIG.MAX_STRINGS or not looks_useful(s) then return end
	captured_set[s] = true
	captured[#captured + 1] = { t = vclock, how = how, s = s }
	for _, pat in R.ipairs(INTERESTING) do
		if R.find(s, pat) then
			event("decoded-string", how .. ": " .. quote(clip(s, 600)))
			break
		end
	end
end

local sb_string = {}
for k, v in R.pairs(string) do sb_string[k] = v end
do
	local o_char, o_gsub, o_format, o_reverse = string.char, string.gsub, string.format, string.reverse
	sb_string.char = function(...)
		check_budget()
		local r = o_char(...)
		capture_string(r, "string.char")
		return r
	end
	sb_string.reverse = function(s)
		local r = o_reverse(s)
		capture_string(r, "string.reverse")
		return r
	end
	sb_string.gsub = function(s, p, r, n)
		check_budget()
		local a, b = o_gsub(s, p, r, n)
		capture_string(a, "string.gsub")
		return a, b
	end
	sb_string.format = function(f, ...)
		local r = o_format(f, ...)
		capture_string(r, "string.format")
		return r
	end
end

local sb_table = {}
for k, v in R.pairs(table) do sb_table[k] = v end
do
	local o_concat = table.concat
	sb_table.concat = function(t, sep, i, j)
		check_budget()
		local r = o_concat(t, sep, i, j)
		capture_string(r, "table.concat")
		return r
	end
end
sandbox.string = sb_string
sandbox.table = sb_table

do
	local o_dec = b64decode
	local function dec(s)
		local r = o_dec(s)
		capture_string(r, "base64decode")
		return r
	end
	sandbox.base64_decode, sandbox.base64decode = dec, dec
	sandbox.crypt.base64decode, sandbox.crypt.base64_decode = dec, dec
	sandbox.crypt.base64.decode = dec
end

do
	local o_wait = sb_wait
	sb_wait = function(t) check_budget(); return o_wait(t) end
	sandbox.task.wait = sb_wait
end

-- ---------- erros engolidos por pcall/xpcall + stubs universais ----------
local swallowed, swallowed_idx = {}, {}
local function swallow(msg)
	msg = clip(safe_tostring(msg), 400)
	local e = swallowed_idx[msg]
	if e then e.n = e.n + 1; return end
	if #swallowed >= CONFIG.MAX_SWALLOWED then return end
	e = { msg = msg, n = 1 }
	swallowed[#swallowed + 1] = e
	swallowed_idx[msg] = e
end

local function pack(...) return { n = R.select("#", ...), ... } end

sandbox.pcall = function(f, ...)
	local r = pack(R.pcall(f, ...))
	if not r[1] then swallow(r[2]) end
	return R.unpack(r, 1, r.n)
end
sandbox.xpcall = function(f, handler, ...)
	local r = pack(R.xpcall(f, function(e)
		swallow(e)
		if R.type(handler) == "function" then return handler(e) end
		return e
	end, ...))
	return R.unpack(r, 1, r.n)
end

local NOSTUB = { Wait = true, Spawn = true, Delay = true, Version = true }

-- rastrear globais indefinidos / novos
R.setmetatable(sandbox, {
	__index = function(t, k)
		if R.type(k) == "string" then
			local c = undefined_globals[k]
			if c then
				undefined_globals[k] = c + 1
			else
				undefined_globals[k] = 1
				undefined_order[#undefined_order + 1] = k
			end
			if CONFIG.AUTO_STUB_UPPER and #k >= 4 and not NOSTUB[k] and R.find(k, "^%u%w+$") then
				local s = ctor_stub(k)
				R.rawset(t, k, s)
				event("auto-stub", k)
				return s
			end
		end
		return nil
	end,
	__newindex = function(t, k, v)
		if R.type(k) == "string" and not written_globals[k] then
			written_globals[k] = true
			written_order[#written_order + 1] = k
		end
		R.rawset(t, k, v)
	end,
})

-- ---------- relatório ----------
local function build_output(run_status, elapsed)
	local out, total, truncated = {}, 0, false
	local limit = CONFIG.MAX_OUTPUT_CHARS
	local function add(s)
		s = R.tostring(s or "")
		if truncated then return false end
		if total + #s > limit then
			out[#out + 1] = "\n-- [output truncated] --\n"
			truncated = true
			return false
		end
		out[#out + 1] = s
		total = total + #s
		return true
	end
	local function section(title, items, fmt_item, share)
		if #items == 0 then return end
		local budget = total + R.floor(limit * share)
		add("\n--=== " .. title .. " ===--\n")
		for i, it in R.ipairs(items) do
			local line = fmt_item(i, it)
			if total + #line > budget then
				add("-- [" .. (#items - i + 1) .. " more omitted] --\n")
				break
			end
			if not add(line) then break end
		end
	end

	add("ENVLOG2-BEGIN\n")
	add("-- run status: " .. run_status .. "\n")
	add("-- elapsed: " .. R.format("%.3fs", elapsed or 0) .. "\n")
	add("-- source bytes: " .. #SOURCE .. " | hash: " .. hash32(SOURCE) .. "\n")
	local fp = fingerprint(SOURCE)
	if #fp > 0 then add("-- detected: " .. R.concat(fp, ", ") .. "\n") end
	add("-- env mode: " .. env_mode .. "\n")
	add("-- prints: " .. #prints .. " | warns: " .. #warns .. " | errors: " .. #errors_list .. "\n")
	add("-- loadstrings: " .. counters.loads .. " (" .. #loads .. " distintos) | requests: " .. counters.requests
		.. " | remotes: " .. counters.remotes .. " | files: " .. counters.files .. "\n")
	add("-- decoded strings: " .. #captured .. " | swallowed errors: " .. #swallowed .. "\n")
	add("-- virtual time: " .. R.format("%.2fs", vclock) .. " | threads: " .. counters.threads
		.. " | resumes: " .. counters.resumes .. " | waits: " .. counters.waits .. "\n")
	if abort_reason then add("-- abort: " .. abort_reason .. "\n") end
	add("-- globals touched: " .. clip(R.concat(undefined_order, ", "), 4000) .. "\n")

	section("PRINTS", prints, function(i, p) return "[" .. i .. "] " .. p .. "\n" end, 0.25)
	section("WARNS", warns, function(i, w) return "[" .. i .. "] " .. w .. "\n" end, 0.05)
	section("ERRORS", errors_list, function(i, e) return "[" .. i .. "] " .. e .. "\n" end, 0.08)
	section("RAISED ERRORS (error() chamado pelo script)", soft_errors, function(i, e) return "[" .. i .. "] " .. e .. "\n" end, 0.03)
	section("LOADSTRINGS", loads, function(i, l)
		local head = "-- load #" .. i .. " | " .. #l.src .. " bytes | hash=" .. l.hash .. " | calls=" .. l.count
			.. (l.name and (" | chunk=" .. clip(l.name, 80)) or "") .. (l.err and (" | compile error: " .. clip(l.err, 300)) or "") .. "\n"
		return head .. clip(l.src, 150000) .. "\n-- end load #" .. i .. " --\n"
	end, 0.30)
	section("DECODED STRINGS", captured, function(i, c)
		return R.format("[%d] (%s @%.2f) %s\n", i, c.how, c.t, quote(clip(c.s, 1500)))
	end, 0.15)
	section("SWALLOWED ERRORS (pcall/xpcall falhou: anti-tamper?)", swallowed, function(i, e)
		return "[" .. i .. "] x" .. e.n .. "  " .. e.msg .. "\n"
	end, 0.05)
	section("EVENTS", events, function(_, e) return R.format("[%7.2f] %s: %s\n", e.t, e.kind, e.text) end, 0.08)
	section("TRACE", trace, function(_, t)
		return R.format("[%7.2f] %-5s %s%s\n", t.t, t.kind, t.text, t.n > 1 and (" (x" .. t.n .. ")") or "")
	end, 0.1)
	if trace_dropped > 0 then add("-- trace: " .. trace_dropped .. " linhas descartadas (MAX_TRACE)\n") end
	if events_dropped > 0 then add("-- events: " .. events_dropped .. " descartados (MAX_EVENTS)\n") end

	local ug = {}
	for i, k in R.ipairs(undefined_order) do
		if i > 500 then break end
		ug[#ug + 1] = k .. " x" .. undefined_globals[k]
	end
	section("UNDEFINED GLOBALS (lidos mas inexistentes)", ug, function(_, s) return s .. "\n" end, 0.02)

	local wg = {}
	for i, k in R.ipairs(written_order) do
		if i > 300 then break end
		local v = R.rawget(sandbox, k)
		wg[#wg + 1] = k .. " = " .. fmt_value(v)
	end
	section("GLOBALS WRITTEN", wg, function(_, s) return s .. "\n" end, 0.02)

	local ic = {}
	for k, v in R.pairs(instances_created) do ic[#ic + 1] = { k, v } end
	R.sort(ic, function(a, b) if a[2] ~= b[2] then return a[2] > b[2] end return a[1] < b[1] end)
	section("INSTANCES CREATED", ic, function(_, e) return e[1] .. " x" .. e[2] .. "\n" end, 0.01)

	if main_returns and #main_returns > 1 then
		local rv = {}
		for i = 2, #main_returns do rv[#rv + 1] = fmt_value(main_returns[i]) end
		section("RETURN VALUE", rv, function(_, s) return s .. "\n" end, 0.01)
	end

	add("\nENVLOG2-END\n")
	return R.concat(out)
end

-- ---------- execução ----------
local chunk, compile_err = compile(SOURCE, "user_script")
if not chunk then
	R.print(build_output("compile error: " .. safe_tostring(compile_err), 0))
	return
end

local main_item = { co = R.create(chunk), wake = 0, main = true }
scheduled[main_item.co] = true
counters.threads = counters.threads + 1

local t0 = R.clock()
cpu_start = t0
resume_item(main_item)
run_scheduler()
local elapsed = R.clock() - t0

local status = "ok"
if main_error then status = "error: " .. main_error end
R.print(build_output(status, elapsed))
