local function test(name, value, expected, fmt)
    if expected ~= value then
        if fmt then
            print(string.format("Failed: " .. name:gsub("%%", "%%%%") .. " Expected: " .. fmt .. " (%s) Got: " .. fmt .. " (%s)", expected, tostring(expected), value, tostring(value)))
        else
            print("Failed: " .. name .. " Expected: " .. tostring(expected) .. " Got: " .. tostring(value))
        end
    else
        print("Passed: " .. name)
    end
end
--jit.off()
test("Default",         `TestHash`,             0x1A106AF1, "%X")
test("{ELF}",           `{ELF}TestHash`,        0x0CAAEF38, "%X")
test("{FNV1}",          `{FNV1}TestHash`,       0x2BC611E9, "%X")
test("{FNV1a}",         `{FNV1a}TestHash`,      0x1A106AF1, "%X")
test("{SDBM}",          `{SDBM}TestHash`,       0x36FB2960, "%X")
test("{!ELF}",          `{!ELF}TestHash`,       0x0CA8ED38, "%X")
test("{!FNV1}",         `{!FNV1}TestHash`,      0xF72411E9, "%X")
test("{!FNV1a}",        `{!FNV1a}TestHash`,     0xA7006B31, "%X")
test("{!SDBM}",         `{!SDBM}TestHash`,      0x03EAD9A0, "%X")

test("Lambda", (`(x) => x + 1`)(3), 4)
local TestValue = 3
test("Scope", (`(x)x=x+TestValue=>x+1`)(1), 5)
TestValue = 4
test("Scope", (`(x)x=x+TestValue=>x+1`)(1), 6)

TestValue += 1
test("+=", TestValue, 5)
TestValue -= 1
test("-=", TestValue, 4)
TestValue *= 2
test("*=", TestValue, 8)
TestValue /= 2
test("/=", TestValue, 4)
TestValue %= 3
test("%=", TestValue, 1)
TestValue &= 2
test("&=", TestValue, 0)
TestValue |= 1
test("|=", TestValue, 1)

test("3 & 3", 3 & 3, 3)
test("0x10101 & 2", 0x10101 & 2, 0)
test("0x10101 & 331", 0x10101 & 331, 257)
test("3 << 2", 3 << 2, 12)
test("~0x10101", ~0x10101, -65794, "%X")
test("~0", ~0, -1, "%X")
test("~132132", ~132132, -132133)
test("0x10101 << 2", 0x10101 << 2, 263172)
test("0x10101 >> 2", 0x10101 >> 2, 16448)
test("0x10101 | 2", 0x10101 | 2, 65795)
test("0x10101 | 331", 0x10101 | 331, 65867)
test("&", (1924076461   & 0xFFFFFFFF),  0x72AF13AD, "%X")
test("&", (461.         &      47295.), 0x8D, "%X")
test("&", (19261.       &    4294965.), 0x935, "%X")
local counter = 2948306269
test("&", (bit.tobit(1924076461+counter) & 0xFFFFFFFF),  0x226AA90A, "%X")
test("&", ((1924076461+counter) & 0x1FFFFFFFF),  0x1226AA90A, "%X")
test("&", (0x1FFFFFFFF & (1924076461+counter)),  0x1226AA90A, "%X")

local MetaValue = setmetatable({
    value = 0x10101,
}, {
__bnot = function (self)
    return ~self.value
end,
__band = function (self, other)
    return self.value & other
end,
__bor = function (self, other)
    return self.value | other
end,
__bxor = function (self, other)
    return self.value ~ other
end,
__shl = function (self, other)
    return self.value << other
end,
__shr = function (self, other)
    return self.value >> other
end,
})
test("Meta !",      ~MetaValue,         bit.bnot(0x10101),          "%X")
test("Meta &",      MetaValue & 0x629B, bit.band(0x10101, 0x629B),  "%X")
test("Meta |",      MetaValue | 0x629B, bit.bor (0x10101, 0x629B),  "%X")
test("Meta ~",      MetaValue ~ 0x629B, bit.bxor(0x10101, 0x629B),  "%X")
test("Meta <<",     MetaValue << 4,     bit.lshift(0x10101, 4),     "%X")
test("Meta >>",     MetaValue >> 4,     bit.rshift(0x10101, 4),     "%X")

local cout = setmetatable({
    fn = nil
}, {
    __shl = function(self, value)
        if type(value) == "string" then
            self.fn(value)
        else
            self.fn(tostring(value))
        end
        return self
    end
})

cout.fn = io.write
local x = { 1, 2, 3, 4, 5 }
print(#x + 1)
local clock = os.clock
local last_wake_click = 0
local message = 0
print(last_wake_click, message)
if last_wake_click > clock() then
end
if message >= 0x0200 then
end
if last_wake_click > clock() and message >= 0x0200 then
end

local concat = setmetatable({ s = "" }, {
    __shl = function(self, v)
       self.s ..= v
       return self
    end,
    __tostring = function(self)
        return self.s
    end,
    __len = function (self)
        return #self.s
    end
})
print(concat << "test" << "\n")

local TestValue = 3
local lambda = `(x) x += TestValue => x + 2`
print(lambda(3)) -- 8
print(#concat)

local f2 = function(n)
    local t = {}
    for i = 1, 32 do
        n = bit.rol(n, 1)
        local r = n & 1
        table.insert(t, r)
    end
    return table.concat(t)
end
print("TEST!START")
print(f2(0x20))
print(f2(0x20))
print(f2(0x20))
print(f2(0x20))
print(f2(0x20))
print("TEST!END")