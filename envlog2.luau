-- envlog2.luau
-- Segundo env logger — versão definitiva
-- Compatível com lune 0.11, WeAreDevs, Prometheus, MoonSec, MoonVeil, LuaObfuscator
-- __SOURCE é injetado pelo bot.py antes deste ficheiro correr

local SOURCE = __SOURCE or ""
local MAX_PRINTS = 2000
local MAX_OUTPUT_CHARS = 500000

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

-- ---------- bit32 ----------
local function to_u32(x)
    x = math.floor(tonumber(x) or 0) % 4294967296
    if x < 0 then x = x + 4294967296 end
    return x
end

local function band(a, b)
    a, b = to_u32(a), to_u32(b)
    local result, bit = 0, 1
    for _ = 1, 32 do
        if (a % 2 == 1) and (b % 2 == 1) then result = result + bit end
        a = math.floor(a / 2); b = math.floor(b / 2); bit = bit * 2
    end
    return result
end

local function bor(a, b)
    a, b = to_u32(a), to_u32(b)
    local result, bit = 0, 1
    for _ = 1, 32 do
        if (a % 2 == 1) or (b % 2 == 1) then result = result + bit end
        a = math.floor(a / 2); b = math.floor(b / 2); bit = bit * 2
    end
    return result
end

local function bxor(a, b)
    a, b = to_u32(a), to_u32(b)
    local result, bit = 0, 1
    for _ = 1, 32 do
        if (a % 2) ~= (b % 2) then result = result + bit end
        a = math.floor(a / 2); b = math.floor(b / 2); bit = bit * 2
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
    band = band, bor = bor, bxor = bxor, lshift = lshift, rshift = rshift, arshift = rshift,
    rol = function(a, b) b = (tonumber(b) or 0) % 32; return to_u32(lshift(a, b) + rshift(a, 32 - b)) end,
    ror = function(a, b) b = (tonumber(b) or 0) % 32; return to_u32(rshift(a, b) + lshift(a, 32 - b)) end,
    bnot = function(a) return to_u32(4294967295 - to_u32(a)) end,
    extract = function(n, field, width) return band(rshift(n, field), 2 ^ ((width or 1)) - 1) end,
    replace = function(n, v, field, width) return n end,
    btest = function(a, b) return band(a, b) ~= 0 end,
    countlz = function(a) return 0 end, countrz = function(a) return 0 end,
}

-- ---------- mocks de objetos ----------
local function mock_object(name)
    local obj = {}
    local mt = {}
    mt.__index = function(t, k)
        if k == "__name" then return name end
        if k == "Name" then return name end
        if k == "ClassName" then return name end
        if k == "Parent" then return nil end
        if k == "WaitForChild" or k == "FindFirstChild" or k == "FindFirstChildOfClass" then
            return function(_, childName) return mock_object(tostring(childName)) end
        end
        if k == "GetChildren" or k == "GetDescendants" then return function() return {} end end
        if k == "GetService" then return function(_, svcName) return mock_object(tostring(svcName)) end end
        if k == "IsA" then return function() return true end end
        if k == "Connect" or k == "Once" then return function() return { Disconnect = function() end } end end
        if k == "Wait" then return function() return mock_object("waitResult") end end
        if k == "Clone" then return function() return mock_object(name) end end
        if k == "Destroy" or k == "ClearAllChildren" then return function() end end
        if k == "FireServer" or k == "FireClient" or k == "FireAllClients" then return function() end end
        if k == "InvokeServer" then return function() return mock_object(name .. "_result") end end
        if k == "InvokeClient" then return function() return mock_object(name .. "_result") end end
        if k == "HttpGet" or k == "HttpGetAsync" then
            return function(_, url)
                record(touched_globals, "HttpGet", tostring(url))
                return "-- fetched from " .. tostring(url) .. "\nprint('mock http')"
            end
        end
        if k == "HttpPost" or k == "HttpPostAsync" then
            return function(_, url, data) record(touched_globals, "HttpPost", tostring(url)); return "{}" end
        end
        if k == "GetAsync" then return function(_, url) record(touched_globals, "GetAsync", tostring(url)); return "" end end
        if k == "PostAsync" then return function(_, url, data) record(touched_globals, "PostAsync", tostring(url)); return "{}" end end
        if k == "JSONDecode" then return function(_, s) return {} end end
        if k == "JSONEncode" then return function(_, t) return "{}" end end
        if k == "GetProductInfo" then return function() return { Name = "MockProduct", PriceInRobux = 0 } end end
        if k == "PromptPurchase" or k == "PromptGamePassPurchase" then return function() end end
        if k == "UserOwnsGamePassAsync" or k == "PlayerOwnsAsset" then return function() return false end end
        if k == "IsClient" then return function() return true end end
        if k == "IsServer" then return function() return false end end
        if k == "IsStudio" then return function() return false end end
        if k == "GetPlayers" then return function() return {} end end
        if k == "GetPlayerFromCharacter" or k == "GetPlayerByUserId" then return function() return mock_object("Player") end end
        if k == "Kick" then return function() end end
        if k == "GetMouse" then return function() return mock_object("Mouse") end end
        if k == "GetMouseLocation" then return function() return { X = 0, Y = 0 } end end
        if k == "IsKeyDown" or k == "IsMouseButtonPressed" then return function() return false end end
        if k == "GetKeysPressed" or k == "GetMouseButtonsPressed" then return function() return {} end end
        if k == "GetFocusedTextBox" then return function() return nil end end
        if k == "RequestAsync" then return function() return { Success = true, StatusCode = 200, Body = "{}" } end end
        if k == "GenerateGUID" then return function() return "00000000-0000-0000-0000-000000000000" end end
        if k == "GetTextSize" then return function() return { X = 100, Y = 20 } end end
        if k == "PreloadAsync" then return function() end end
        if k == "AddItem" then return function() end end
        if k == "PlayLocalSound" then return function() end end
        if k == "Create" then return function() return mock_object("tween") end end
        if k == "Play" or k == "Pause" or k == "Cancel" or k == "Stop" then return function() end end
        if k == "Raycast" then return function() return { Instance = mock_object("hit"), Position = { X = 0, Y = 0, Z = 0 }, Normal = { X = 0, Y = 0, Z = 1 } } end end
        if k == "GetTouchingParts" or k == "GetConnectedParts" then return function() return {} end end
        if k == "GetMass" then return function() return 1 end end
        if k == "MoveTo" then return function() end end
        if k == "ChangeState" then return function() end end
        if k == "TakeDamage" then return function() end end
        if k == "GetState" then return function() return mock_object("Enum.HumanoidStateType.Running") end end
        if k == "LoadAnimation" then return function() return mock_object("AnimationTrack") end end
        if k == "GetPlayingAnimationTracks" then return function() return {} end end
        if k == "BindToRenderStep" then return function(_, name, prio, fn) if type(fn) == "function" then pcall(fn, 0.016) end end end
        if k == "UnbindFromRenderStep" then return function() end end
        if k == "GetPropertyChangedSignal" then return function() return mock_object(name .. ".Changed") end end
        if k == "CreateCollisionGroup" then return function() return 1 end end
        if k == "GetTagged" then return function() return {} end end
        if k == "AddTag" or k == "RemoveTag" then return function() end end
        if k == "GetInstanceAddedSignal" or k == "GetInstanceRemovedSignal" then return function() return mock_object("Signal") end end
        if k == "CreatePath" then return function() return mock_object("Path") end end
        if k == "Teleport" or k == "TeleportToPlaceInstance" then return function() end end
        if k == "GetGuiInset" then return function() return { X = 0, Y = 36 } end end
        if k == "GetBoundingBox" then return function() return { X = 0, Y = 0, Z = 0 }, { X = 1, Y = 1, Z = 1 } end end
        if k == "GetExtentsSize" then return function() return { X = 1, Y = 1, Z = 1 } end end
        if k == "GetPrimaryPartCFrame" or k == "GetPivot" then return function() return mock_object("CFrame") end end
        if k == "SetPrimaryPartCFrame" or k == "PivotTo" then return function() end end
        if k == "TranslateBy" then return function() end end
        if k == "BreakJoints" or k == "MakeJoints" then return function() end end
        if k == "Resize" then return function() end end
        if k == "GetNetworkOwner" then return function() return mock_object("Player") end end
        if k == "SetNetworkOwner" then return function() end end
        if k == "CanSetNetworkOwnership" then return function() return false end end
        -- propriedades comuns
        if k == "Position" or k == "Origin" or k == "Target" then return { X = 0, Y = 5, Z = 0 } end
        if k == "Size" then return { X = 1, Y = 1, Z = 1 } end
        if k == "Value" then return 0 end
        if k == "Text" or k == "PlaceholderText" then return "" end
        if k == "Visible" or k == "Enabled" or k == "Anchored" or k == "CanCollide" then return true end
        if k == "Playing" or k == "IsPlaying" or k == "Looped" then return false end
        if k == "Health" or k == "MaxHealth" then return 100 end
        if k == "WalkSpeed" then return 16 end
        if k == "JumpPower" or k == "JumpHeight" then return 50 end
        if k == "UserId" then return 1 end
        if k == "DisplayName" then return "Player" end
        if k == "AccountAge" then return 1000 end
        if k == "FieldOfView" then return 70 end
        if k == "CFrame" then return mock_object("CFrame") end
        if k == "LookVector" then return { X = 0, Y = 0, Z = -1 } end
        if k == "RightVector" then return { X = 1, Y = 0, Z = 0 } end
        if k == "UpVector" then return { X = 0, Y = 1, Z = 0 } end
        if k == "Magnitude" then return 0 end
        if k == "Unit" then return { X = 0, Y = 0, Z = 1 } end
        if k == "X" or k == "Y" or k == "Z" or k == "W" then return 0 end
        if k == "R" or k == "G" or k == "B" then return 1 end
        -- fallback
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
    "rawlen", "setmetatable", "getmetatable", "unpack", "require", "collectgarbage",
    "coroutine", "utf8"
}
for _, name in ipairs(base_names) do
    if _G[name] ~= nil then sandbox[name] = _G[name] end
end

sandbox.print = function(...) record(captured_prints, ...) end
sandbox.warn = function(...) record(captured_warns, ...) end
sandbox.error = function(...) record(captured_errors, ...); error(...) end
sandbox.loadstring = mock_loadstring
sandbox.load = mock_loadstring
sandbox.getfenv = function(f) return sandbox end
sandbox.setfenv = function(f, env) return f end
sandbox.getgenv = function() return sandbox end
sandbox.newproxy = function(mt) return setmetatable({}, mt or {}) end
sandbox.bit32 = bit32_mock
sandbox.bit = bit32_mock
sandbox.bit32 = bit32_mock

-- ROBLOX GLOBAL
sandbox.game = mock_object("Game")
sandbox.workspace = mock_object("Workspace")
sandbox.script = mock_object("Script")
sandbox.shared = {}
sandbox.Instance = { new = mock_instance_new, fromExisting = function(o) return mock_object("Copy") end }
sandbox.Vector3 = { new = function(x, y, z) return mock_vector3(x, y, z) end, zero = mock_vector3(0,0,0), one = mock_vector3(1,1,1) }
sandbox.Vector2 = { new = function(x, y) return { X = x or 0, Y = y or 0 } end }
sandbox.CFrame = { new = function() return mock_object("CFrame") end, Angles = function() return mock_object("CFrame") end, lookAt = function() return mock_object("CFrame") end }
sandbox.Color3 = { new = function(r, g, b) return { R = r or 0, G = g or 0, B = b or 0 } end, fromRGB = function() return { R = 0, G = 0, B = 0 } end }
sandbox.BrickColor = { new = function() return mock_object("BrickColor") end, new = function() return mock_object("BrickColor") end }
sandbox.UDim = { new = function(s, o) return { Scale = s or 0, Offset = o or 0 } end }
sandbox.UDim2 = { new = function() return mock_object("UDim2") end }
sandbox.Rect = { new = function() return mock_object("Rect") end }
sandbox.Region3 = { new = function() return mock_object("Region3") end }
sandbox.Ray = { new = function() return mock_object("Ray") end }
sandbox.NumberRange = { new = function() return mock_object("NumberRange") end }
sandbox.NumberSequence = { new = function() return mock_object("NumberSequence") end }
sandbox.ColorSequence = { new = function() return mock_object("ColorSequence") end }
sandbox.NumberSequenceKeypoint = { new = function() return mock_object("NumberSequenceKeypoint") end }
sandbox.ColorSequenceKeypoint = { new = function() return mock_object("ColorSequenceKeypoint") end }
sandbox.PhysicalProperties = { new = function() return mock_object("PhysicalProperties") end }
sandbox.Font = { new = function() return mock_object("Font") end }
sandbox.RaycastParams = { new = function() return mock_object("RaycastParams") end }
sandbox.OverlapParams = { new = function() return mock_object("OverlapParams") end }
sandbox.PathWaypoint = { new = function() return mock_object("PathWaypoint") end }
sandbox.Faces = { new = function() return mock_object("Faces") end }
sandbox.Axes = { new = function() return mock_object("Axes") end }
sandbox.Vector3int16 = { new = function() return mock_vector3(0,0,0) end }
sandbox.Vector2int16 = { new = function() return { X = 0, Y = 0 } end }
sandbox.CatalogSearchParams = { new = function() return mock_object("CatalogSearchParams") end }
sandbox.DateTime = { now = function() return mock_object("DateTime") end, fromUnixTimestamp = function() return mock_object("DateTime") end }
sandbox.TweenInfo = { new = function() return mock_object("TweenInfo") end }
sandbox.Enum = mock_object("Enum")
sandbox.Random = { new = function() 
    local r = {}
    function r:NextNumber(a,b) return (a or 0) + 0.5 * ((b or 1) - (a or 0)) end
    function r:NextInteger(a,b) return math.floor((a or 1) + 0.5 * ((b or 100) - (a or 1))) end
    function r:NextUnitVector() return { X = 0.5, Y = 0.5, Z = 0.5 } end
    function r:Shuffle(t) return t end
    function r:Clone() return sandbox.Random.new() end
    return r
end }
sandbox.task = {
    wait = function(t) return 0 end,
    spawn = function(f, ...) if type(f) == "function" then pcall(f, ...) end end,
    delay = function(t, f, ...) if type(f) == "function" then pcall(f, ...) end end,
    defer = function(f, ...) if type(f) == "function" then pcall(f, ...) end end,
    cancel = function() end,
    synchronize = function() end,
    desynchronize = function() end,
}
sandbox.wait = function(t) return t or 0 end
sandbox.spawn = function(f, ...) if type(f) == "function" then pcall(f, ...) end end
sandbox.delay = function(t, f, ...) if type(f) == "function" then pcall(f, ...) end end
sandbox.tick = function() return os.clock() end
sandbox.time = function() return os.clock() end
sandbox.elapsedTime = function() return os.clock() end
sandbox.os = os
sandbox.string = string
sandbox.table = table
sandbox.math = math
sandbox.coroutine = coroutine
sandbox.utf8 = utf8 or {}

-- DEBUG mock (importante para alguns obfuscators)
sandbox.debug = {
    getinfo = function() return { source = "=", what = "Lua", name = "?", namewhat = "", currentline = 0, nups = 0, nparams = 0, isvararg = false, func = function() end } end,
    getupvalue = function() return nil end,
    setupvalue = function() return nil end,
    getlocal = function() return nil end,
    setlocal = function() return nil end,
    traceback = function() return "" end,
    sethook = function() end,
    gethook = function() return nil end,
    profilebegin = function() end,
    profileend = function() end,
    getmetatable = getmetatable,
    setmetatable = setmetatable,
}

-- FUNÇÕES DE EXPLOIT
sandbox.hookfunction = function(f, g) return f end
sandbox.hookmetamethod = function(obj, method, f) return function() end end
sandbox.newcclosure = function(f) return f end
sandbox.replaceclosure = function(f, g) return f end
sandbox.checkcaller = function() return true end
sandbox.iscclosure = function(f) return false end
sandbox.islclosure = function(f) return type(f) == "function" end
sandbox.getrawmetatable = function(obj) return getmetatable(obj) or {} end
sandbox.setreadonly = function(obj, v) return obj end
sandbox.make_writeable = function(obj) return obj end
sandbox.make_readonly = function(obj) return obj end
sandbox.isreadonly = function(obj) return false end
sandbox.getrenv = function() return sandbox end
sandbox.getgc = function() return {} end
sandbox.getinstances = function() return {} end
sandbox.getnilinstances = function() return {} end
sandbox.getconnections = function() return {} end
sandbox.getscripts = function() return {} end
sandbox.getrunningscripts = function() return {} end
sandbox.getloadedmodules = function() return {} end
sandbox.getcallingscript = function() return sandbox.script end
sandbox.firesignal = function() end
sandbox.fireclickdetector = function() end
sandbox.fireproximityprompt = function() end
sandbox.firetouchinterest = function() end
sandbox.setclipboard = function(s) end
sandbox.getclipboard = function() return "" end
sandbox.identifyexecutor = function() return "envlog2", "2.0" end
sandbox.getexecutorname = function() return "envlog2" end
sandbox.gethwid = function() return "HWID-MOCK" end
sandbox.request = function(opts) return { Success = true, StatusCode = 200, StatusMessage = "OK", Headers = {}, Body = "{}" } end
sandbox.http_request = sandbox.request
sandbox.syn = { request = sandbox.request }
sandbox.http = { request = sandbox.request }
sandbox.fluxus = { request = sandbox.request }
sandbox.secure_call = function(f, ...) return f(...) end
sandbox.create_secure_function = function(f) return f end
sandbox.getthreadidentity = function() return 7 end
sandbox.setthreadidentity = function() end
sandbox.getidentity = function() return 7 end
sandbox.setidentity = function() end
sandbox.getthreadcontext = function() return 7 end
sandbox.setthreadcontext = function() end
sandbox.getcustomasset = function(f) return "rbxasset://" .. tostring(f) end
sandbox.getsynasset = function(f) return "rbxasset://" .. tostring(f) end
sandbox.getinfo = function(f) return { source = "=", what = "Lua", name = "?", short_src = "envlog2" } end
sandbox.getconstants = function(f) return {} end
sandbox.getupvalues = function(f) return {} end
sandbox.getprotos = function(f) return {} end
sandbox.getupvalue = function(f, i) return nil end
sandbox.setupvalue = function(f, i, v) end
sandbox.setconstant = function(f, i, v) end
sandbox.getconstant = function(f, i) return nil end
sandbox.getproto = function(f, i) return function() end end
sandbox.setproto = function(f, i, p) end
sandbox.getstack = function(f, i) return nil end
sandbox.setstack = function(f, i, v) end
sandbox.rconsoleprint = function(s) end
sandbox.rconsoleclear = function() end
sandbox.rconsolecreate = function() end
sandbox.rconsoledestroy = function() end
sandbox.rconsoleinput = function() return "" end
sandbox.rconsoleinfo = function(s) end
sandbox.rconsolewarn = function(s) end
sandbox.rconsoleerr = function(s) end
sandbox.rconsolename = function(s) end
sandbox.printconsole = function(s) end
sandbox.setfflag = function(name, v) end
sandbox.getfflag = function(name) return "" end
sandbox.setfpscap = function(n) end
sandbox.getfpscap = function() return 60 end
sandbox.isnetworkowner = function(part) return true end
sandbox.gethiddenproperty = function(inst, prop) return nil end
sandbox.sethiddenproperty = function(inst, prop, v) end
sandbox.setsimulationradius = function(r1, r2) end
sandbox.getspecialinfo = function(inst) return {} end
sandbox.saveinstance = function(opts) end
sandbox.decompile = function(script) return "-- decompiled" end
sandbox.lz4compress = function(s) return s end
sandbox.lz4decompress = function(s) return s end
sandbox.MessageBox = function(a, b, c) return 1 end
sandbox.setwindowactive = function() end
sandbox.setwindowtitle = function(s) end
sandbox.queue_on_teleport = function(s) end
sandbox.queueonteleport = function(s) end
sandbox.isvalidinstance = function(inst) return inst ~= nil end
sandbox.validcheck = function(inst) return inst ~= nil end
sandbox.protectgui = function(gui) end
sandbox.gethui = function() return mock_object("HiddenUI") end
sandbox.gethiddenui = function() return mock_object("HiddenUI") end
sandbox.iswindowactive = function() return true end
sandbox.isrbxactive = function() return true end
sandbox.isgameactive = function() return true end
sandbox.mouse1click = function() end
sandbox.mouse1press = function() end
sandbox.mouse1release = function() end
sandbox.mouse2click = function() end
sandbox.mouse2press = function() end
sandbox.mouse2release = function() end
sandbox.mousemoverel = function(x, y) end
sandbox.mousemoveabs = function(x, y) end
sandbox.mousescroll = function(n) end
sandbox.keypress = function(k) end
sandbox.keyrelease = function(k) end
sandbox.keyclick = function(k) end
sandbox.base64_encode = function(s) return s end
sandbox.base64_decode = function(s) return s end
sandbox.base64encode = function(s) return s end
sandbox.base64decode = function(s) return s end
sandbox.crypt = {
    base64encode = function(s) return s end,
    base64decode = function(s) return s end,
    base64_encode = function(s) return s end,
    base64_decode = function(s) return s end,
    encrypt = function(s, k) return s end,
    decrypt = function(s, k) return s end,
    hash = function(s) return "hash" end,
    generatekey = function(n) return string.rep("0", n or 32) end,
    generatebytes = function(n) return string.rep("\0", n or 16) end,
}
sandbox.Drawing = {
    new = function(kind) return mock_object("Drawing_" .. tostring(kind)) end,
    Fonts = mock_object("Drawing.Fonts"),
}

-- settings / usersettings
sandbox.settings = function() return { GetFFlag = function() return false end, GetFVariable = function() return "" end, SetFFlag = function() end } end
sandbox.UserSettings = function() return { GameSettings = { TouchCameraMovementMode = sandbox.Enum.TouchCameraMovementMode, VideoQuality = sandbox.Enum.VideoQualityLevel } } end
sandbox.UserGameSettings = { GameSettings = {} }

-- __index / __newindex do sandbox
setmetatable(sandbox, {
    __index = function(t, k)
        record(touched_globals, tostring(k))
        return nil
    end,
    __newindex = function(t, k, v) rawset(t, k, v) end,
})

-- ---------- expor no _G (para scripts que usam getfenv() e esperam o ambiente) ----------
_G.getfenv = function(f) return sandbox end
_G.setfenv = function(f, env) return f end
_G.getgenv = function() return sandbox end
_G.newproxy = function(mt) return setmetatable({}, mt or {}) end
_G.game = sandbox.game
_G.workspace = sandbox.workspace
_G.script = sandbox.script
_G.Instance = sandbox.Instance
_G.Vector3 = sandbox.Vector3
_G.Vector2 = sandbox.Vector2
_G.CFrame = sandbox.CFrame
_G.Color3 = sandbox.Color3
_G.BrickColor = sandbox.BrickColor
_G.UDim = sandbox.UDim
_G.UDim2 = sandbox.UDim2
_G.Rect = sandbox.Rect
_G.Region3 = sandbox.Region3
_G.Ray = sandbox.Ray
_G.NumberRange = sandbox.NumberRange
_G.NumberSequence = sandbox.NumberSequence
_G.ColorSequence = sandbox.ColorSequence
_G.NumberSequenceKeypoint = sandbox.NumberSequenceKeypoint
_G.ColorSequenceKeypoint = sandbox.ColorSequenceKeypoint
_G.PhysicalProperties = sandbox.PhysicalProperties
_G.Font = sandbox.Font
_G.RaycastParams = sandbox.RaycastParams
_G.OverlapParams = sandbox.OverlapParams
_G.PathWaypoint = sandbox.PathWaypoint
_G.Faces = sandbox.Faces
_G.Axes = sandbox.Axes
_G.Vector3int16 = sandbox.Vector3int16
_G.Vector2int16 = sandbox.Vector2int16
_G.CatalogSearchParams = sandbox.CatalogSearchParams
_G.DateTime = sandbox.DateTime
_G.TweenInfo = sandbox.TweenInfo
_G.Enum = sandbox.Enum
_G.Random = sandbox.Random
_G.task = sandbox.task
_G.wait = sandbox.wait
_G.spawn = sandbox.spawn
_G.delay = sandbox.delay
_G.tick = sandbox.tick
_G.time = sandbox.time
_G.elapsedTime = sandbox.elapsedTime
_G.bit32 = sandbox.bit32
_G.bit = sandbox.bit
_G.loadstring = sandbox.loadstring
_G.load = sandbox.load
_G.unpack = sandbox.unpack or table.unpack
_G.debug = sandbox.debug
_G.shared = sandbox.shared

-- ---------- output ----------
local function build_output(run_status, elapsed)
    local out = {}
    local total = 0
    local function add(s)
        s = tostring(s or "")
        if total + #s > MAX_OUTPUT_CHARS then out[#out + 1] = "\n-- [output truncated] --\n"; return false end
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

-- ---------- execução ----------
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

if type(setfenv) == "function" then
    pcall(setfenv, chunk, sandbox)
end

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
