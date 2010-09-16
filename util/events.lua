-- Prosody IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
-- 
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--


local pairs = pairs;
local t_insert = table.insert;
local t_sort = table.sort;

module "events"

function new()
	local handlers = {};
	local event_map = {};
	local function _rebuild_index(event) -- TODO optimize index rebuilding
		local _handlers = event_map[event];
		local index = handlers[event];
		if index then
			for i=#index,1,-1 do index[i] = nil; end
		else index = {}; handlers[event] = index; end
		for handler in pairs(_handlers) do
			t_insert(index, handler);
		end
		t_sort(index, function(a, b) return _handlers[a] > _handlers[b]; end);
	end;
	local function add_handler(event, handler, priority)
		local map = event_map[event];
		if map then
			map[handler] = priority or 0;
		else
			map = {[handler] = priority or 0};
			event_map[event] = map;
		end
		_rebuild_index(event);
	end;
	local function remove_handler(event, handler)
		local map = event_map[event];
		if map then
			map[handler] = nil;
			_rebuild_index(event);
		end
	end;
	local function add_handlers(handlers)
		for event, handler in pairs(handlers) do
			add_handler(event, handler);
		end
	end;
	local function remove_handlers(handlers)
		for event, handler in pairs(handlers) do
			remove_handler(event, handler);
		end
	end;
	local function fire_event(event, ...)
		local h = handlers[event];
		if h then
			for i=1,#h do
				local ret = h[i](...);
				if ret ~= nil then return ret; end
			end
		end
	end;
	return {
		add_handler = add_handler;
		remove_handler = remove_handler;
		add_handlers = add_handlers;
		remove_handlers = remove_handlers;
		fire_event = fire_event;
		_handlers = handlers;
		_event_map = event_map;
	};
end

return _M;
