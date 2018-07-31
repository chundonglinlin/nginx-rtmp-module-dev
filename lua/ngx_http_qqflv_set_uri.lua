local function ngx_http_qqflv_set_uri()
	local uri = ngx.var.uri
	local m = ngx.re.match(uri, [=[.*(/[^/]+\.flv)$]=])
	if not m then return end
	ngx.req.set_uri(m[1])	
end

ngx_http_qqflv_set_uri()

