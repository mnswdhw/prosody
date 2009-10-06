-- Prosody IM
-- Copyright (C) 2008-2009 Matthew Wild
-- Copyright (C) 2008-2009 Waqas Hussain
-- 
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--



local hosts = hosts;
local sessions = sessions;
local core_process_stanza = function(a, b) core_process_stanza(a, b); end
local add_task = require "util.timer".add_task;
local socket = require "socket";
local format = string.format;
local t_insert, t_sort = table.insert, table.sort;
local get_traceback = debug.traceback;
local tostring, pairs, ipairs, getmetatable, newproxy, error, tonumber
    = tostring, pairs, ipairs, getmetatable, newproxy, error, tonumber;

local idna_to_ascii = require "util.encodings".idna.to_ascii;
local connlisteners_get = require "net.connlisteners".get;
local wrapclient = require "net.server".wrapclient;
local modulemanager = require "core.modulemanager";
local st = require "stanza";
local stanza = st.stanza;
local nameprep = require "util.encodings".stringprep.nameprep;

local fire_event = require "core.eventmanager".fire_event;
local uuid_gen = require "util.uuid".generate;

local logger_init = require "util.logger".init;

local log = logger_init("s2smanager");

local sha256_hash = require "util.hashes".sha256;

local dialback_secret = uuid_gen();

local adns, dns = require "net.adns", require "net.dns";

local connect_timeout = config.get("*", "core", "s2s_timeout") or 60;
local dns_timeout = config.get("*", "core", "dns_timeout") or 60;
local max_dns_depth = config.get("*", "core", "dns_max_depth") or 3;

incoming_s2s = {};
local incoming_s2s = incoming_s2s;

module "s2smanager"

local function compare_srv_priorities(a,b) return a.priority < b.priority or a.weight < b.weight; end

local function bounce_sendq(session)
	local sendq = session.sendq;
	if sendq then
		session.log("info", "sending error replies for "..#sendq.." queued stanzas because of failed outgoing connection to "..tostring(session.to_host));
		local dummy = {
			type = "s2sin";
			send = function(s)
				(session.log or log)("error", "Replying to to an s2s error reply, please report this! Traceback: %s", get_traceback());
			end;
			dummy = true;
		};
		for i, data in ipairs(sendq) do
			local reply = data[2];
			local xmlns = reply.attr.xmlns;
			if not xmlns or xmlns == "jabber:client" or xmlns == "jabber:server" then
				reply.attr.type = "error";
				reply:tag("error", {type = "cancel"})
					:tag("remote-server-not-found", {xmlns = "urn:ietf:params:xml:ns:xmpp-stanzas"}):up();
				core_process_stanza(dummy, reply);
			end
			sendq[i] = nil;
		end
		session.sendq = nil;
	end
end

function send_to_host(from_host, to_host, data)
	local host = hosts[from_host].s2sout[to_host];
	if host then
		-- We have a connection to this host already
		if host.type == "s2sout_unauthed" and data.name ~= "db:verify" and ((not data.xmlns) or data.xmlns == "jabber:client" or data.xmlns == "jabber:server") then
			(host.log or log)("debug", "trying to send over unauthed s2sout to "..to_host);
			if not host.notopen and not host.dialback_key and host.sends2s then
				host.log("debug", "dialback had not been initiated");
				initiate_dialback(host);
			end
			
			-- Queue stanza until we are able to send it
			if host.sendq then t_insert(host.sendq, {tostring(data), st.reply(data)});
			else host.sendq = { {tostring(data), st.reply(data)} }; end
			host.log("debug", "stanza [%s] queued ", data.name);
		elseif host.type == "local" or host.type == "component" then
			log("error", "Trying to send a stanza to ourselves??")
			log("error", "Traceback: %s", get_traceback());
			log("error", "Stanza: %s", tostring(data));
		else
			(host.log or log)("debug", "going to send stanza to "..to_host.." from "..from_host);
			-- FIXME
			if host.from_host ~= from_host then
				log("error", "WARNING! This might, possibly, be a bug, but it might not...");
				log("error", "We are going to send from %s instead of %s", tostring(host.from_host), tostring(from_host));
			end
			host.sends2s(data);
			host.log("debug", "stanza sent over "..host.type);
		end
	else
		log("debug", "opening a new outgoing connection for this stanza");
		local host_session = new_outgoing(from_host, to_host);
		-- Store in buffer
		host_session.sendq = { {tostring(data), st.reply(data)} };
		log("debug", "stanza [%s] queued until connection complete", tostring(data.name));
		if (not host_session.connecting) and (not host_session.conn) then
			log("warn", "Connection to %s failed already, destroying session...", to_host);
			destroy_session(host_session);
		end
	end
end

local open_sessions = 0;

function new_incoming(conn)
	local session = { conn = conn, type = "s2sin_unauthed", direction = "incoming", hosts = {} };
	if true then
		session.trace = newproxy(true);
		getmetatable(session.trace).__gc = function () open_sessions = open_sessions - 1; end;
	end
	open_sessions = open_sessions + 1;
	local w, log = conn.write, logger_init("s2sin"..tostring(conn):match("[a-f0-9]+$"));
	session.log = log;
	session.sends2s = function (t) log("debug", "sending: %s", tostring(t)); w(tostring(t)); end
	incoming_s2s[session] = true;
	add_task(connect_timeout, function ()
		if session.conn ~= conn or
		   session.type == "s2sin" then
			return; -- Ok, we're connect[ed|ing]
		end
		-- Not connected, need to close session and clean up
		(session.log or log)("warn", "Destroying incomplete session %s->%s due to inactivity", 
		    session.from_host or "(unknown)", session.to_host or "(unknown)");
		session:close("connection-timeout");
	end);
	return session;
end

function new_outgoing(from_host, to_host)
		local host_session = { to_host = to_host, from_host = from_host, host = from_host, 
		                       notopen = true, type = "s2sout_unauthed", direction = "outgoing" };
		
		hosts[from_host].s2sout[to_host] = host_session;
		
		local log;
		do
			local conn_name = "s2sout"..tostring(host_session):match("[a-f0-9]*$");
			log = logger_init(conn_name);
			host_session.log = log;
		end
		
		-- This is the first call, can't fail (the first step is DNS lookup)
		attempt_connection(host_session);
		
		if not host_session.sends2s then		
			-- A sends2s which buffers data (until the stream is opened)
			-- note that data in this buffer will be sent before the stream is authed
			-- and will not be ack'd in any way, successful or otherwise
			local buffer;
			function host_session.sends2s(data)
				if not buffer then
					buffer = {};
					host_session.send_buffer = buffer;
				end
				log("debug", "Buffering data on unconnected s2sout to %s", to_host);
				buffer[#buffer+1] = data;
				log("debug", "Buffered item %d: %s", #buffer, tostring(data));
			end
			
		end

		return host_session;
end


function attempt_connection(host_session, err)
	local from_host, to_host = host_session.from_host, host_session.to_host;
	local connect_host, connect_port = idna_to_ascii(to_host), 5269;
	
	if not err then -- This is our first attempt
		log("debug", "First attempt to connect to %s, starting with SRV lookup...", to_host);
		host_session.connecting = true;
		local handle;
		handle = adns.lookup(function (answer)
			handle = nil;
			host_session.connecting = nil;
			if answer then
				log("debug", to_host.." has SRV records, handling...");
				local srv_hosts = {};
				host_session.srv_hosts = srv_hosts;
				for _, record in ipairs(answer) do
					t_insert(srv_hosts, record.srv);
				end
				t_sort(srv_hosts, compare_srv_priorities);
				
				local srv_choice = srv_hosts[1];
				host_session.srv_choice = 1;
				if srv_choice then
					connect_host, connect_port = srv_choice.target or to_host, srv_choice.port or connect_port;
					log("debug", "Best record found, will connect to %s:%d", connect_host, connect_port);
				end
			else
				log("debug", to_host.." has no SRV records, falling back to A");
			end
			-- Try with SRV, or just the plain hostname if no SRV
			local ok, err = try_connect(host_session, connect_host, connect_port);
			if not ok then
				if not attempt_connection(host_session, err) then
					-- No more attempts will be made
					destroy_session(host_session);
				end
			end
		end, "_xmpp-server._tcp."..connect_host..".", "SRV");
		
		-- Set handler for DNS timeout
		add_task(dns_timeout, function ()
			if handle then
				adns.cancel(handle, true);
			end
		end);
		
		log("debug", "DNS lookup for %s sent, waiting for response before we can connect", to_host);
		return true; -- Attempt in progress
	elseif host_session.srv_hosts and #host_session.srv_hosts > host_session.srv_choice then -- Not our first attempt, and we also have SRV
		host_session.srv_choice = host_session.srv_choice + 1;
		local srv_choice = host_session.srv_hosts[host_session.srv_choice];
		connect_host, connect_port = srv_choice.target or to_host, srv_choice.port or connect_port;
		host_session.log("info", "Connection failed (%s). Attempt #%d: This time to %s:%d", tostring(err), host_session.srv_choice, connect_host, connect_port);
	else
		host_session.log("info", "Out of connection options, can't connect to %s", tostring(host_session.to_host));
		-- We're out of options
		return false;
	end
	
	if not (connect_host and connect_port) then
		-- Likely we couldn't resolve DNS
		log("warn", "Hmm, we're without a host (%s) and port (%s) to connect to for %s, giving up :(", tostring(connect_host), tostring(connect_port), tostring(to_host));
		return false;
	end
	
	return try_connect(host_session, connect_host, connect_port);
end

function try_connect(host_session, connect_host, connect_port)
	host_session.connecting = true;
	local handle;
	handle = adns.lookup(function (reply)
		handle = nil;
		host_session.connecting = nil;
		
		-- COMPAT: This is a compromise for all you CNAME-(ab)users :)
		if not (reply and reply[#reply] and reply[#reply].a) then
			local count = max_dns_depth;
			reply = dns.peek(connect_host, "CNAME", "IN");
			while count > 0 and reply and reply[#reply] and not reply[#reply].a and reply[#reply].cname do
				log("debug", "Looking up %s (DNS depth is %d)", tostring(reply[#reply].cname), count);
				reply = dns.peek(reply[#reply].cname, "A", "IN") or dns.peek(reply[#reply].cname, "CNAME", "IN");
				count = count - 1;
			end
		end
		-- end of CNAME resolving
		
		if reply and reply[#reply] and reply[#reply].a then
			log("debug", "DNS reply for %s gives us %s", connect_host, reply[#reply].a);
			return make_connect(host_session, reply[#reply].a, connect_port);
		else
			log("debug", "DNS lookup failed to get a response for %s", connect_host);
			if not attempt_connection(host_session, "name resolution failed") then -- Retry if we can
				log("debug", "No other records to try for %s - destroying", host_session.to_host);
				destroy_session(host_session); -- End of the line, we can't
			end
		end
	end, connect_host, "A", "IN");

	-- Set handler for DNS timeout
	add_task(dns_timeout, function ()
		if handle then
			adns.cancel(handle, true);
		end
	end);
		
	return true;
end

function make_connect(host_session, connect_host, connect_port)
	host_session.log("info", "Beginning new connection attempt to %s (%s:%d)", host_session.to_host, connect_host, connect_port);
	-- Ok, we're going to try to connect
	
	local from_host, to_host = host_session.from_host, host_session.to_host;
	
	local conn, handler = socket.tcp()

	conn:settimeout(0);
	local success, err = conn:connect(connect_host, connect_port);
	if not success and err ~= "timeout" then
		log("warn", "s2s connect() to %s (%s:%d) failed: %s", host_session.to_host, connect_host, connect_port, err);
		return false, err;
	end
	
	local cl = connlisteners_get("xmppserver");
	conn = wrapclient(conn, connect_host, connect_port, cl, cl.default_mode or 1, hosts[from_host].ssl_ctx, false );
	host_session.conn = conn;
	
	-- Register this outgoing connection so that xmppserver_listener knows about it
	-- otherwise it will assume it is a new incoming connection
	cl.register_outgoing(conn, host_session);
	
	local w = conn.write;
	host_session.sends2s = function (t) log("debug", "sending: %s", tostring(t)); w(tostring(t)); end
	
	conn.write(format([[<stream:stream xmlns='jabber:server' xmlns:db='jabber:server:dialback' xmlns:stream='http://etherx.jabber.org/streams' from='%s' to='%s' version='1.0' xml:lang='en'>]], from_host, to_host));
	log("debug", "Connection attempt in progress...");
	add_task(connect_timeout, function ()
		if host_session.conn ~= conn or
		   host_session.type == "s2sout" or
		   host_session.connecting then
			return; -- Ok, we're connect[ed|ing]
		end
		-- Not connected, need to close session and clean up
		(host_session.log or log)("warn", "Destroying incomplete session %s->%s due to inactivity", 
		    host_session.from_host or "(unknown)", host_session.to_host or "(unknown)");
		host_session:close("connection-timeout");
	end);
	return true;
end

function streamopened(session, attr)
	local send = session.sends2s;
	
	-- TODO: #29: SASL/TLS on s2s streams
	session.version = tonumber(attr.version) or 0;
	
	if session.secure == false then
		session.secure = true;
	end
	
	if session.version >= 1.0 and not (attr.to and attr.from) then
		
		(session.log or log)("warn", "Remote of stream "..(session.from_host or "(unknown)").."->"..(session.to_host or "(unknown)")
			.." failed to specify to (%s) and/or from (%s) hostname as per RFC", tostring(attr.to), tostring(attr.from));
	end
	
	if session.direction == "incoming" then
		-- Send a reply stream header
		session.to_host = attr.to and nameprep(attr.to);
		session.from_host = attr.from and nameprep(attr.from);
	
		session.streamid = uuid_gen();
		(session.log or log)("debug", "incoming s2s received <stream:stream>");
		send("<?xml version='1.0'?>");
		send(stanza("stream:stream", { xmlns='jabber:server', ["xmlns:db"]='jabber:server:dialback', 
				["xmlns:stream"]='http://etherx.jabber.org/streams', id=session.streamid, from=session.to_host, version=(session.version > 0 and "1.0" or nil) }):top_tag());
		if session.to_host and not hosts[session.to_host] then
			-- Attempting to connect to a host we don't serve
			session:close({ condition = "host-unknown"; text = "This host does not serve "..session.to_host });
			return;
		end
		if session.version >= 1.0 then
			local features = st.stanza("stream:features");
			fire_event("s2s-stream-features", session, features);
			
			log("debug", "Sending stream features: %s", tostring(features));
			send(features);
		end
	elseif session.direction == "outgoing" then
		-- If we are just using the connection for verifying dialback keys, we won't try and auth it
		if not attr.id then error("stream response did not give us a streamid!!!"); end
		session.streamid = attr.id;
	
		-- Send unauthed buffer
		-- (stanzas which are fine to send before dialback)
		-- Note that this is *not* the stanza queue (which 
		-- we can only send if auth succeeds) :)
		local send_buffer = session.send_buffer;
		if send_buffer and #send_buffer > 0 then
			log("debug", "Sending s2s send_buffer now...");
			for i, data in ipairs(send_buffer) do
				session.sends2s(tostring(data));
				send_buffer[i] = nil;
			end
		end
		session.send_buffer = nil;
	
		-- If server is pre-1.0, don't wait for features, just do dialback
		if session.version < 1.0 then
			if not session.dialback_verifying then
				log("debug", "Initiating dialback...");
				initiate_dialback(session);
			else
				mark_connected(session);
			end
		end
	end

	session.notopen = nil;
end

function streamclosed(session)
	(session.log or log)("debug", "</stream:stream>");
	if session.sends2s then
		session.sends2s("</stream:stream>");
	end
	session.notopen = true;
end

function initiate_dialback(session)
	-- generate dialback key
	session.dialback_key = generate_dialback(session.streamid, session.to_host, session.from_host);
	session.sends2s(format("<db:result from='%s' to='%s'>%s</db:result>", session.from_host, session.to_host, session.dialback_key));
	session.log("info", "sent dialback key on outgoing s2s stream");
end

function generate_dialback(id, to, from)
	return sha256_hash(id..to..from..dialback_secret, true);
end

function verify_dialback(id, to, from, key)
	return key == generate_dialback(id, to, from);
end

function make_authenticated(session, host)
	if session.type == "s2sout_unauthed" then
		session.type = "s2sout";
	elseif session.type == "s2sin_unauthed" then
		session.type = "s2sin";
		if host then
			session.hosts[host].authed = true;
		end
	elseif session.type == "s2sin" and host then
		session.hosts[host].authed = true;
	else
		return false;
	end
	session.log("debug", "connection %s->%s is now authenticated", session.from_host or "(unknown)", session.to_host or "(unknown)");
	
	mark_connected(session);
	
	return true;
end

-- Stream is authorised, and ready for normal stanzas
function mark_connected(session)
	local sendq, send = session.sendq, session.sends2s;
	
	local from, to = session.from_host, session.to_host;
	
	session.log("info", session.direction.." s2s connection "..from.."->"..to.." complete");
	
	local send_to_host = send_to_host;
	function session.send(data) send_to_host(to, from, data); end
	
	
	if session.direction == "outgoing" then
		if sendq then
			session.log("debug", "sending "..#sendq.." queued stanzas across new outgoing connection to "..session.to_host);
			for i, data in ipairs(sendq) do
				send(data[1]);
				sendq[i] = nil;
			end
			session.sendq = nil;
		end
		
		session.srv_hosts = nil;
	end
end

function destroy_session(session)
	(session.log or log)("info", "Destroying "..tostring(session.direction).." session "..tostring(session.from_host).."->"..tostring(session.to_host));
	
	if session.direction == "outgoing" then
		hosts[session.from_host].s2sout[session.to_host] = nil;
		bounce_sendq(session);
	elseif session.direction == "incoming" then
		incoming_s2s[session] = nil;
	end
	
	for k in pairs(session) do
		if k ~= "trace" then
			session[k] = nil;
		end
	end
end

return _M;
