local _M = {}
local lzw = require("lualzw")
local input = require("input-text")

local function compress_file(data)
    local out = lzw.compress(data)
end

function _M.doit()
    compress_file(input.data)
end

-- run if outside nginx
if not package.loaded["ngx"] then
  print(_M.doit())
end

return _M
