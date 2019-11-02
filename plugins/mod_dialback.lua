-- Prosody IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
--
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--

local hosts = _G.hosts;

local log = module._log;

local st = require "util.stanza";
local sha256_hash = require "util.hashes".sha256;
local sha256_hmac = require "util.hashes".hmac_sha256;
local nameprep = require "util.encodings".stringprep.nameprep;
local uuid_gen = require"util.uuid".generate;

local xmlns_stream = "http://etherx.jabber.org/streams";

local dialback_requests = setmetatable({}, { __mode = 'v' });

local dialback_secret = sha256_hash(module:get_option_string("dialback_secret", uuid_gen()), true);
local dwd = module:get_option_boolean("dialback_without_dialback", false);

--- Helper to check that a session peer's certificate is valid
function check_cert_status(session)
	local host = session.direction == "outgoing" and session.to_host or session.from_host
	local conn = session.conn:socket()
	local cert
	if conn.getpeercertificate then
		cert = conn:getpeercertificate()
	end

	return module:fire_event("s2s-check-certificate", { host = host, session = session, cert = cert });
end


function module.save()
	return { dialback_secret = dialback_secret };
end

function module.restore(state)
	dialback_secret = state.dialback_secret;
end

function generate_dialback(id, to, from)
	return sha256_hmac(dialback_secret, to .. ' ' .. from .. ' ' .. id, true);
end

function initiate_dialback(session)
	-- generate dialback key
	session.dialback_key = generate_dialback(session.streamid, session.to_host, session.from_host);
	session.sends2s(st.stanza("db:result", { from = session.from_host, to = session.to_host }):text(session.dialback_key));
	session.log("debug", "sent dialback key on outgoing s2s stream");
end

function verify_dialback(id, to, from, key)
	return key == generate_dialback(id, to, from);
end

module:hook("stanza/jabber:server:dialback:verify", function(event)
	local origin, stanza = event.origin, event.stanza;

	if origin.type == "s2sin_unauthed" or origin.type == "s2sin" then
		-- We are being asked to verify the key, to ensure it was generated by us
		origin.log("debug", "verifying that dialback key is ours...");
		local attr = stanza.attr;
		if attr.type then
			module:log("warn", "Ignoring incoming session from %s claiming a dialback key for %s is %s",
				origin.from_host or "(unknown)", attr.from or "(unknown)", attr.type);
			return true;
		end
		-- COMPAT: Grr, ejabberd breaks this one too?? it is black and white in XEP-220 example 34
		--if attr.from ~= origin.to_host then error("invalid-from"); end
		local type;
		if verify_dialback(attr.id, attr.from, attr.to, stanza[1]) then
			type = "valid"
		else
			type = "invalid"
			origin.log("warn", "Asked to verify a dialback key that was incorrect. An imposter is claiming to be %s?", attr.to);
		end
		origin.log("debug", "verified dialback key... it is %s", type);
		origin.sends2s(st.stanza("db:verify", { from = attr.to, to = attr.from, id = attr.id, type = type }):text(stanza[1]));
		return true;
	end
end);

module:hook("stanza/jabber:server:dialback:result", function(event)
	local origin, stanza = event.origin, event.stanza;

	if origin.type == "s2sin_unauthed" or origin.type == "s2sin" then
		-- he wants to be identified through dialback
		-- We need to check the key with the Authoritative server
		local attr = stanza.attr;
		if not attr.to or not attr.from then
			origin.log("debug", "Missing Dialback addressing (from=%q, to=%q)", attr.from, attr.to);
			origin:close("improper-addressing");
			return true;
		end
		local to, from = nameprep(attr.to), nameprep(attr.from);

		if not hosts[to] then
			-- Not a host that we serve
			origin.log("warn", "%s tried to connect to %s, which we don't serve", from, to);
			origin:close("host-unknown");
			return true;
		elseif not from then
			origin:close("improper-addressing");
		end

		if dwd and origin.secure then
			if check_cert_status(origin, from) == false then
				return
			elseif origin.cert_chain_status == "valid" and origin.cert_identity_status == "valid" then
				origin.sends2s(st.stanza("db:result", { to = from, from = to, id = attr.id, type = "valid" }));
				module:fire_event("s2s-authenticated", { session = origin, host = from });
				return true;
			end
		end

		origin.hosts[from] = { dialback_key = stanza[1] };

		dialback_requests[from.."/"..origin.streamid] = origin;

		-- COMPAT: ejabberd, gmail and perhaps others do not always set 'to' and 'from'
		-- on streams. We fill in the session's to/from here instead.
		if not origin.from_host then
			origin.from_host = from;
		end
		if not origin.to_host then
			origin.to_host = to;
		end

		origin.log("debug", "asking %s if key %s belongs to them", from, stanza[1]);
		module:fire_event("route/remote", {
			from_host = to, to_host = from;
			stanza = st.stanza("db:verify", { from = to, to = from, id = origin.streamid }):text(stanza[1]);
		});
		return true;
	end
end);

module:hook("stanza/jabber:server:dialback:verify", function(event)
	local origin, stanza = event.origin, event.stanza;

	if origin.type == "s2sout_unauthed" or origin.type == "s2sout" then
		local attr = stanza.attr;
		local dialback_verifying = dialback_requests[attr.from.."/"..(attr.id or "")];
		if dialback_verifying and attr.from == origin.to_host then
			local valid;
			if attr.type == "valid" then
				module:fire_event("s2s-authenticated", { session = dialback_verifying, host = attr.from });
				valid = "valid";
			else
				-- Warn the original connection that is was not verified successfully
				log("warn", "authoritative server for %s denied the key", attr.from or "(unknown)");
				valid = "invalid";
			end
			if dialback_verifying.destroyed then
				log("warn", "Incoming s2s session %s was closed in the meantime, so we can't notify it of the dialback result",
					tostring(dialback_verifying):match("%w+$"));
			else
				dialback_verifying.sends2s(
						st.stanza("db:result", { from = attr.to, to = attr.from, id = attr.id, type = valid })
								:text(dialback_verifying.hosts[attr.from].dialback_key));
			end
			dialback_requests[attr.from.."/"..(attr.id or "")] = nil;
		end
		return true;
	end
end);

module:hook("stanza/jabber:server:dialback:result", function(event)
	local origin, stanza = event.origin, event.stanza;

	if origin.type == "s2sout_unauthed" or origin.type == "s2sout" then
		-- Remote server is telling us whether we passed dialback

		local attr = stanza.attr;
		if not hosts[attr.to] then
			origin:close("host-unknown");
			return true;
		elseif hosts[attr.to].s2sout[attr.from] ~= origin then
			-- This isn't right
			origin:close("invalid-id");
			return true;
		end
		if stanza.attr.type == "valid" then
			module:fire_event("s2s-authenticated", { session = origin, host = attr.from });
		else
			origin:close("not-authorized", "dialback authentication failed");
		end
		return true;
	end
end);

module:hook_tag("urn:ietf:params:xml:ns:xmpp-sasl", "failure", function (origin, stanza) -- luacheck: ignore 212/stanza
	if origin.external_auth == "failed" then
		module:log("debug", "SASL EXTERNAL failed, falling back to dialback");
		initiate_dialback(origin);
		return true;
	end
end, 100);

module:hook_tag(xmlns_stream, "features", function (origin, stanza) -- luacheck: ignore 212/stanza
	if not origin.external_auth or origin.external_auth == "failed" then
		module:log("debug", "Initiating dialback...");
		initiate_dialback(origin);
		return true;
	end
end, 100);

module:hook("s2sout-authenticate-legacy", function (event)
	module:log("debug", "Initiating dialback...");
	initiate_dialback(event.origin);
	return true;
end, 100);

-- Offer dialback to incoming hosts
module:hook("s2s-stream-features", function (data)
	data.features:tag("dialback", { xmlns='urn:xmpp:features:dialback' }):up();
end);
