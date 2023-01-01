local inet = require('inet')
local lpeg = require('lpeg')
local renumber = require('kres_modules.renumber')

local function add_inet(rr_list, netw)
	if inet.is4(netw) then
		table.insert(rr_list, renumber.prefix(netw:cidrstring(), '0.0.0.0'))
		local ip6_mask = 96 + netw:len()
		local ip6_subnet = '::ffff:'..netw:ipstring()..'/'..ip6_mask
		table.insert(rr_list, renumber.prefix(ip6_subnet, '::'))
	elseif inet.is6(netw) then
		table.insert(rr_list, renumber.prefix(netw:cidrstring(), '::'))
	else
		error('netw is not an inet table')
	end
end

local function add_inet_set(rr_list, inet_set)
	for _, netw in ipairs(inet_set:list()) do
		add_inet(rr_list, netw)
	end
end

local function is_rr_match(rr_list, rr)
	for i = 1, #rr_list do
		local prefix = rr_list[i]
		-- Match record type to address family and record address to given subnet
		if renumber.match_subnet(prefix[1], prefix[2], prefix[4], rr) then
			return true
		end
	end
	return false
end

local function lpeg_anywhere(p)
    return (1 - lpeg.P(p))^0 * p
end

local WhiteListEntry = {}
WhiteListEntry.__index = WhiteListEntry

setmetatable(WhiteListEntry, {
    __call = function(cls, ...)
        return cls:new(...)
    end
})

function WhiteListEntry:new(str_dname, ...)
    local rr_list = {}
    for _, v in ipairs({...}) do
    	if inet.is(v) then
    		add_inet(rr_list, v)
    	elseif inet.is_set(v) then
    		add_int_set(rr_list, v)
		else
    		local netw = inet(v)
	    	if not netw then
	    		error('Invalid network: '..v)
	    	end
	    	add_inet(rr_list, netw)
    	end
    end

    -- normalize domain name (add '.') at end, as that is what incoming queries have
    if str_dname[#str_dname] ~= '.' then
    	str_dname = str_dname .. '.'
    end
    -- create lpeg pattern to match dname
    local dname_lpeg = lpeg_anywhere(lpeg.P(str_dname) * -1)

    return setmetatable({dname = str_dname, dname_lpeg = dname_lpeg, rr_list = rr_list}, self);
end

function WhiteListEntry:match(rr, qry_dname)
	if not lpeg.match(self.dname_lpeg, qry_dname) then
		return false
	end
	return is_rr_match(self.rr_list, rr)
end

local rebindwl = {
	whiteListEntry = WhiteListEntry,
	add_inet = add_inet,
	add_inet_set = add_inet_set,
	is_rr_match = is_rr_match
}

return rebindwl
