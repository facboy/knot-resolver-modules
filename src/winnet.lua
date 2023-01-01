---
--- Meant for use in knot-resolver, only b/c it uses log_info
--- Created by Christopher Ng.
--- DateTime: 01/01/2023 20:24
---

local ffi = require('ffi')

local winnet = {}

local function ltrim(str)
    return str:gsub('^%s+', '')
end

local function rtrim(str)
    return str:gsub('%s+$', '')
end

local function get_netsh_lookup()
    local netsh_lookup = {}

    -- get descriptions from wmic
    local wmic_h = io.popen('netsh trace show interfaces')
    local ret, err = pcall(function()
        local name
        for line in wmic_h:lines() do
            local split, _ = line:find(':', 1, true)
            if split then
                local field = line:sub(1, split - 1)
                if field:find('^%w') then
                    -- header line, wipe fields
                    name = nil
                else
                    field = ltrim(field)
                    -- need to rtrim as well as there is a carriage return at the end which causes odd behaviour
                    local value = rtrim(ltrim(line:sub(split + 1)))
                    if field == 'Description' then
                        name = value
                    elseif field == 'Interface GUID' then
                        if not name then
                            error('Invalid output from "netsh trace", found "Interface Guid" before "Description"')
                        end
                        -- add guid/name pair to lookup
                        netsh_lookup[value] = name
                    end
                end
            end
        end
    end)
    wmic_h:close()
    if not ret then
        error(err)
    end

    return netsh_lookup
end

local function get_wmic_lookup()
    local wmic_lookup = {}

    -- get descriptions from wmic
    local wmic_h = io.popen('wmic nicconfig get settingid,description')
    local ret, err = pcall(function()
        local i = 1, split
        for line in wmic_h:lines() do
            if i == 1 then
                -- header line, parse it to find where to split
                split, _ = line:find('SettingID', 1, true)
            else
                local name = rtrim(line:sub(1, split - 1))
                -- need to trim as well as there is a carriage return at the end which causes odd behaviour
                local guid = rtrim(line:sub(split))
                if #name > 0 then
                    wmic_lookup[guid] = name
                end
            end
            i = i + 1
        end
    end)
    wmic_h:close()
    if not ret then
        error(err)
    end
    return wmic_lookup
end

function winnet.get_windows_interfaces()
    local interfaces = {}
    local win_lookup = get_netsh_lookup()

    for guid, intf in pairs(net:interfaces()) do
        local name = win_lookup[guid]
        if name then
            interfaces[name] = intf
        else
            -- look for localhost
            local addr1 = intf.addr[1]
            if addr1 == '::1' or addr1 == '127.0.0.1' then
                interfaces['localhost'] = intf
            else
                log_warn(ffi.C.LOG_GRP_NETWORK, 'Unknown interface found, addr = [%s]', table.concat(intf.addr, ', '))
            end
        end
    end

    do
        local interface_names = {}
        for name, _ in pairs(interfaces) do
            table.insert(interface_names, name)
        end
        table.sort(interface_names, function(a, b) return a:lower() < b:lower() end)
        log_info(ffi.C.LOG_GRP_NETWORK, 'Found interfaces:')
        for i = 1, #interface_names do
            log_info(ffi.C.LOG_GRP_NETWORK, '\t%s', interface_names[i])
        end
    end

    return interfaces
end

return winnet
