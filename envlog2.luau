-- envlog2.luau
-- Segundo env logger — compatível com lune 0.11
-- __SOURCE é injetado pelo bot.py antes deste ficheiro correr

local SOURCE = __SOURCE or ""
local MAX_PRINTS = 1000
local MAX_OUTPUT_CHARS = 200000

local captured_prints = {}
local captured_warns = {}
local captured_errors = {}
local touched_globals = {}

local function record(tbl, ...)
    if #tbl >= MAX_PRINTS then return end
    local parts = {}
    for i = 1, select("#", ...) do
        local ok, s = pcall(tostring, select(i, ...))
        parts[#parts + 1] = ok and s or "<tostring error>"
    end
    tbl[#tbl + 1] = table.concat(parts, "\t")
end

-- ---------- bit32 mock (sem & | ~ << >>) ----------
local function to_u32(x)
    x = math.floor(tonumber(x) or 0) % 4294967296
    if x < 0 then x = x + 4294967296 end
    return x
end

local function band(a, b)
    a, b = to_u32(a), to_u32(b)
    local result, bit = 0, 1
    for _ = 1, 32 do
        if (a % 2 == 1) and (b % 2 == 1) then
            result = result + bit
        end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        bit = bit * 2
    end
    return result
end

local function bor(a, b)
    a, b = to_u32(a), to_u32(b)
    local result, bit = 0, 1
    for _ = 1, 32 do
        if (a % 2 == 1) or (b % 2 == 1) then
            result = result + bit
        end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        bit = bit * 2
    end
    return result
end

local function bxor(a, b)
    a, b = to_u32(a), to_u32(b)
    local result, bit = 0, 1
    for _ = 1, 32 do
        if (a % 2) ~= (b % 2) then
            result = result + bit
        end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        bit = bit * 2
    end
    return result
end

local function lshift(a, n)
    n = (tonumber(n) or 0) % 32
    return to_u32(to_u32(a) * (2 ^ n))
end

local function rshift(a, n)
    n = (tonumber(n) or 0) % 32
    return to_u32(math.floor(to_u32(a) / (2 ^ n)))
end

local bit32_mock = {
    band = band,
    bor = bor,
    bxor = bxor,
    lshift = lshift,
    rshift = rshift,
    arshift = rshift,
    rol = function(a, b)
        b = (tonumber(b) or 0) % 32
        return to_u32(lshift(a, b) + rshift(a, 32 - b))
    end,
    ror = function(a, b)
        b = (tonumber(b) or 0) % 32
        return to_u32(rshift(a, b) + lshift(a, 32 - b))
    end,
    bnot = function(a)
        return to_u32(4294967295 - to_u32(a))
    end,
    extract = function(n, field, width)
        return band(rshift(n, field), 2 ^ ((width or 1)) - 1)
    end,
    replace = function(n, v, field, width)
        return n
    end,
    btest = function(a, b)
        return band(a, b) ~= 0
    end,
    countlz = function(a) return 0 end,
    countrz = function(a) return 0 end,
}

-- ---------- mocks ----------
local function mock_object(name)
    local obj = {}
    local mt = {}
    mt.__index = function(t, k)
        if k == "__name" then return name end
        if k == "Name" then return name end
        if k == "ClassName" then return name end
        if k == "Parent" then return nil end
        if k == "WaitForChild" or k == "FindFirstChild" then
            return function(_, childName) return mock_object(tostring(childName)) end
        end
        if k == "GetChildren" or k == "GetDescendants" then
            return function() return {} end
        end
        if k == "GetService" then
            return function(_, svcName) return mock_object(tostring(svcName)) end
        end
        if k == "IsA" then
            return function() return true end
        end
        if k == "Connect" then
            return function() return { Disconnect = function() end } end
        end
        if k == "Clone" then
            return function() return mock_object(name) end
        end
        if k == "Destroy" then
            return function() end
        end
        if k == "FireServer" or k == "FireClient" or k == "FireAllClients" then
            return function() end
        end
        if k == "InvokeServer" then
            return function() return mock_object(name .. "_result") end
        end
        if k == "Position" then return { X = 0, Y = 0, Z = 0 } end
        if k == "Size" then return { X = 1, Y = 1, Z = 1 } end
        if k == "Value" then return 0 end
        if k == "Text" then return "" end
        if k == "Visible" then return true end
        return mock_object(name .. "." .. tostring(k))
    end
    mt.__newindex = function(t, k, v) end
    mt.__tostring = function() return name end
    mt.__call = function() return mock_object(name .. "()") end
    return setmetatable(obj, mt)
end

local function mock_vector3(x, y, z)
    local v = {}
    local mt = {}
    mt.__index = function(t, k)
        if k == "X" then return x or 0 end
        if k == "Y" then return y or 0 end
        if k == "Z" then return z or 0 end
        if k == "Magnitude" then return math.sqrt((x or 0)^2 + (y or 0)^2 + (z or 0)^2) end
        if k == "Unit" then return mock_vector3(0, 0, 1) end
        return function() return mock_vector3(0, 0, 0) end
    end
    mt.__tostring = function() return string.format("Vector3(%s, %s, %s)", tostring(x), tostring(y), tostring(z)) end
    mt.__add = function(a, b) return mock_vector3((x or 0) + (b.X or 0), (y or 0) + (b.Y or 0), (z or 0) + (b.Z or 0)) end
    mt.__sub = function(a, b) return mock_vector3((x or 0) - (b.X or 0), (y or 0) - (b.Y or 0), (z or 0) - (b.Z or 0)) end
    mt.__mul = function(a, b)
        if type(b) == "number" then return mock_vector3((x or 0) * b, (y or 0) * b, (z or 0) * b) end
        return mock_vector3(0, 0, 0)
    end
    return setmetatable(v, mt)
end

local function mock_instance_new(className, parent)
    record(touched_globals, "Instance.new", tostring(className))
    return mock_object(tostring(className))
end

local function mock_loadstring(code, chunkname)
    record(touched_globals, "loadstring", tostring(chunkname))
    local loader = load or loadstring
    if not loader then
        record(captured_errors, "loadstring failed: no load function")
        return nil, "no load function"
    end
    local fn, err = loader(code, chunkname or "chunk")
    if not fn then
        record(captured_errors, "loadstring failed: " .. tostring(err))
        return nil, err
    end
    return fn
end

-- ---------- sandbox ----------
local sandbox = {}

local base_names = {
    "print", "warn", "error", "pcall", "xpcall", "assert", "select", "type", "typeof",
    "tostring", "tonumber", "pairs", "ipairs", "next", "rawget", "rawset", "rawequal",
    "rawlen", "setmetatable", "getmetatable", "unpack", "require", "collectgarbage"
}
for _, name in ipairs(base_names) do
    if _G[name] ~= nil then
        sandbox[name] = _G[name]
    end
end

sandbox.print = function(...) record(captured_prints, ...) end
sandbox.warn = function(...) record(captured_warns, ...) end
sandbox.error = function(...) record(captured_errors, ...); error(...) end
sandbox.loadstring = mock_loadstring
sandbox.load = mock_loadstring
sandbox.getfenv = function(f) return sandbox end
sandbox.setfenv = function(f, env) return f end
sandbox.getgenv = function() return sandbox end
sandbox.bit32 = bit32_mock
sandbox.bit = bit32_mock

sandbox.game = mock_object("Game")
sandbox.workspace = mock_object("Workspace")
sandbox.script = mock_object("Script")
sandbox.shared = {}
sandbox.Instance = { new = mock_instance_new }
sandbox.Vector3 = { new = function(x, y, z) return mock_vector3(x, y, z) end }
sandbox.Vector2 = { new = function(x, y) return { X = x or 0, Y = y or 0 } end }
sandbox.CFrame = { new = function() return mock_object("CFrame") end }
sandbox.Color3 = { new = function(r, g, b) return { R = r or 0, G = g or 0, B = b or 0 } end }
sandbox.UDim = { new = function(s, o) return { Scale = s or 0, Offset = o or 0 } end }
sandbox.UDim2 = { new = function() return mock_object("UDim2") end }
sandbox.Enum = mock_object("Enum")
sandbox.task = {
    wait = function(t) return 0 end,
    spawn = function(f, ...) if type(f) == "function" then pcall(f, ...) end end,
    delay = function(t, f, ...) if type(f) == "function" then pcall(f, ...) end end,
    defer = function(f, ...) if type(f) == "function" then pcall(f, ...) end end,
}
sandbox.wait = function(t) return t or 0 end
sandbox.spawn = function(f, ...) if type(f) == "function" then pcall(f, ...) end end
sandbox.delay = function(t, f, ...) if type(f) == "function" then pcall(f, ...) end end
sandbox.tick = function() return os.clock() end
sandbox.time = function() return os.clock() end
sandbox.os = os
sandbox.string = string
sandbox.table = table
sandbox.math = math
sandbox.coroutine = coroutine
sandbox.utf8 = utf8 or {}

setmetatable(sandbox, {
    __index = function(t, k)
        record(touched_globals, tostring(k))
        return nil
    end,
    __newindex = function(t, k, v)
        rawset(t, k, v)
    end,
})

-- ---------- output ----------
local function build_output(run_status, elapsed)
    local out = {}
    local total = 0
    local function add(s)
        s = tostring(s or "")
        if total + #s > MAX_OUTPUT_CHARS then
            out[#out + 1] = "\n-- [output truncated] --\n"
            return false
        end
        out[#out + 1] = s
        total = total + #s
        return true
    end

    add("ENVLOG2-BEGIN\n")
    add("-- run status: " .. run_status .. "\n")
    add("-- elapsed: " .. string.format("%.3fs", elapsed or 0) .. "\n")
    add("-- source bytes: " .. #SOURCE .. "\n")
    add("-- prints: " .. #captured_prints .. " | warns: " .. #captured_warns .. " | errors: " .. #captured_errors .. "\n")
    add("-- globals touched: " .. table.concat(touched_globals, ", ") .. "\n")

    if #captured_prints > 0 then
        add("\n--=== PRINTS ===--\n")
        for i, p in ipairs(captured_prints) do
            if not add("[" .. i .. "] " .. p .. "\n") then break end
        end
    end
    if #captured_warns > 0 then
        add("\n--=== WARNS ===--\n")
        for i, w in ipairs(captured_warns) do
            if not add("[" .. i .. "] " .. w .. "\n") then break end
        end
    end
    if #captured_errors > 0 then
        add("\n--=== ERRORS ===--\n")
        for i, e in ipairs(captured_errors) do
            if not add("[" .. i .. "] " .. e .. "\n") then break end
        end
    end

    add("\nENVLOG2-END\n")
    return table.concat(out)
end

-- ---------- execução (defensiva) ----------
local loader = load or loadstring
if not loader then
    print("ENVLOG2-BEGIN\n-- FATAL: no load function available\nENVLOG2-END")
    return
end

local chunk, compile_err = loader(SOURCE, "user_script")
if not chunk then
    print(build_output("compile error: " .. tostring(compile_err), 0))
    return
end

-- setfenv opcional (lune pode não ter)
if type(setfenv) == "function" then
    pcall(setfenv, chunk, sandbox)
end

-- os.clock opcional
local clock = (type(os) == "table" and type(os.clock) == "function") and os.clock or function() return 0 end

local start = clock()
local ok, runtime_err = pcall(chunk)
local elapsed = clock() - start

local status
if ok then
    status = "ok"
else
    status = "error: " .. tostring(runtime_err)
    record(captured_errors, "runtime: " .. tostring(runtime_err))
end

print(build_output(status, elapsed))
