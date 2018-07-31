local function ngx_http_qqflv_rewrite()
	local uri = ngx.var.uri
	local m = ngx.re.match(uri, [=[.*(/[^/]+)\.flv$]=])
	if not m then return end
	local protocol = tonumber(ngx.var.arg_protocol)
	local playback, source, buname
	if protocol == 1795 or protocol == 1797 then
		return ngx.exec("/p2p" .. ngx.var.uri, ngx.var.args)
	end
	if tonumber(ngx.var.arg_xhttptrunk) == 1 then
		source = true
	elseif ngx.var.http_pragma == "xHttpTrunk=1" then
		source = true
	end

	if source then
		return ngx.exec("/source" .. ngx.var.uri, "xHttpTrunk=1")
	end

	playback = tonumber(ngx.var.arg_restreamtimeabs) or tonumber(ngx.var.arg_wsstreamtimeabc)
	 		or tonumber(ngx.var.arg_playback) or tonumber(ngx.var.arg_rsec)

	if playback then
		return ngx.exec("/playback" .. ngx.var.uri, ngx.var.args)
	end

	if ngx.var.arg_buname == "qt" or ngx.var.arg_buname == "qtlol" then
		buname = true
	end


	if buname then
		return ngx.exec("/live" .. m[1] .. "Q", ngx.var.args)
	else
		return ngx.exec("/live" .. m[1] .. "F", ngx.var.args)
	end
end

ngx_http_qqflv_rewrite()

