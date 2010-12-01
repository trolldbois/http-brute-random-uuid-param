description = [[

This nmap NSE script is a learning test tool.

It's aim is to try 'brute-force' attempts on guessing valid values for a UUID parameter.


let's say you have a website protecting download data by obscurity/UUID :

Valid query :
 http://dl.example.org/dl/?uuid=f410c7b6-68ad-407a-99f5-71b34f12e819
 -> returns a file
 Expected Headers :

HTTP/1.0 200 OK
Expires: Thu, 01 Jan 1970 00:00:00 GMT
title: Service dl: myfile pdf
Server: IBM_HTTP_Server
Content-Disposition: attachment; filename="russian_brides.pdf"
Content-Length: 70884
Date: Wed, 01 Dec 2010 01:34:55 GMT
Content-Transfer-Encoding: binary
Content-Type: application/pdf
Length: 70884 (69K) [application/pdf]


Invalid query :
 http://dl.example.org/dl/?uuid=f410c7b6-68ad-407a-99f5-71b34f12e819
 -> returns a 200 - user level error page
 Expected Headers :
HTTP/1.0 200 OK
Server: IBM_HTTP_Server
Date: Wed, 01 Dec 2010 01:34:15 GMT
Content-Language: fr-FR
Content-Type: text/html; charset=UTF-8
Length: unspecified [text/html] 


Here we will choose to discriminate on header['expires'] ( nmap header gets all tolower() ).



]]

---
-- @usage
-- OTHEROPTS="-T3 --min-parallelism=2 --max-parallelism=2 -d1 --stats-every=10m -oA myscan.log"
-- TARGETS=dl.example.org
-- HOSTNAME=dl.example.org
-- URI="/?"
-- ARG=uuid
-- PORT=80
--
-- nmap -n $TARGETS -p $PORT --script=./http-brute-random-uuid-param.nse --script-arg=hostname=$HOSTNAME,method=$METHOD,uri="$URI",arg=$ARG,limit=$LIMIT --host-timeout=$TIMEOUT $OTHEROPTS
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-brute-param:
-- |   Tested:2/2
-- |   Found: 2
-- |   uuid:494b1cd5-3df5-42b0-b277-047f42c7f975
-- |_  uuid:9907b58a-ac2b-40b2-9103-8b6f06f7c5ae
--
-- Summary
-- -------
--
-- @args http-brute-random-uuid-param.path points to the path protected by authentication
-- @args http-brute-random-uuid-param.hostname sets the host header in case of virtual 
--       hosting
-- @args http-brute-random-uuid-param.uservar sets the http-variable name that holds the
--		 username used to authenticate. A simple autodetection of this variable
--       is attempted.
-- @args http-brute-random-uuid-param.passvar sets the http-variable name that holds the
--		 password used to authenticate. A simple autodetection of this variable
--       is attempted.


--
-- Version 0.1
-- Created 2010/11/30 - v0.1 - created by Loic Jaquemet <loic.jaquemet+nmap@gmail.com>
--

author = "Loic Jaquemet"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive"}

require "comm"
require "shortport"
require "stdnse"
require "http"
require "uuid"


local print_response = function(response)
--  response = {
--    status=nil,
--    ["status-line"]=nil,
--    header={},
--    rawheader={},
--    body=""
--  }
  stdnse.print_debug(" ** RESPONSE ** ") 
  stdnse.print_debug(" ** status: %s",response.status) 
  stdnse.print_debug(" ** headers: ") 
  for i,h in pairs(response.header) do
    stdnse.print_debug(" ** Header[%s]: %s",i,h)   
  end    
  
  
end





local get_uuid = function()
  return uuid.new()
end

--- Validates the HTTP response and checks for modifications.
--@param response The HTTP response from the server.
--@param original The original HTTP request sent to the server.
--@return A string describing the changes (if any) between the response and
-- request.

local validate = function(response)
	local start, stop
	local body

  -- cheating 
	if not response:match("HTTP/1.[01] 200") or
	   not response:match("Expires: Thu, 01 Jan 1970 00:00:00 GMT") then
		return false
	end

  stdnse.print_debug("Found file") 
  stdnse.print_debug("Found Expires : ") 

  return true
  
end



local brute_param = function(host,port,hostname,method,uri,param)
  local tested = {}
  local found = {}
  local nb = 0   
	local options = {
		header = {
      -- set Host: header
			Host = hostname,
			["User-Agent"]  = "Mozilla/5.0 (compatible; One; two)",
		},
  }
  
  for i = 0, 100, 1 do
  
    local uuid = get_uuid()
    stdnse.print_debug("Generated " .. uuid) 
	  tested[i] = uuid

	  local cmd = uri .. param .. "=" .. uuid .. " HTTP/1.0\r\n\r\n"

    -- pipeline should be better...
    -- options are not parsed :/
	  local sd, response = comm.tryssl(host, port, cmd, options)
	  if not sd then 
		  stdnse.print_debug("Unable to open connection") 
		  return
	  end
	  if validate(response) then
	    found[nb] = uuid
	    nb=nb+1
		  stdnse.print_debug("Found " .. uuid) 
	  end
	end  
	
	return "Found " .. found
end


--  response = {
--    status=nil,
--    ["status-line"]=nil,
--    header={},
--    rawheader={},
--    body=""
--  }

local validate_p = function(response)
	local start, stop
	local body

  -- cheating 
	if response.status ~= 200 or
	   response.header["expires"] == nil then
		return false
	end
  stdnse.print_debug("Found Expires : ") 

	if response.header["content-disposition"] == nil then
	  local ctnt = ""
    stdnse.print_debug("No file attached ??!!")
    print_response(response) 
  else
    ctnt=response.header["content-disposition"]
    filename=string.sub(ctnt,string.find(ctnt,'="(%w)')+2,-2)
    if filename ~= nil then
      stdnse.print_debug("Found file " .. filename) 
    end
	end

	--table.insert(response.rawheader, "(Request type: " .. request_type .. ")")

  return true
  
end



local brute_param_pipeline = function(host,port,hostname,method,uri,param,limit)
  local tested = {}
  local found = {}
  local all = {}
  local uuids = {}
	local options = {
		header = {
      -- set Host: header
			Host = hostname,
			["User-Agent"]  = "Mozilla/5.0 (compatible; One; two)",
		},
  }
    
  for i = 1, limit, 1 do
      
    local uuid = get_uuid()
    --stdnse.print_debug("Generated " .. uuid) 
	  tested[i] = uuid
    
    local path = uri .. param .. "=" .. uuid
    
    stdnse.print_debug(1,"Queuing %s",path) 
    -- host, port , path, options, cookies, allrequests
		all = http.pGet(host, port, path, options, nil, all)
		--all = http.pipeline_add(path,options,all)
  end

  --local uuid='8a9ff85d-849c-4a05-8709-769a4a065845'
  --tested[#tested+1] = uuid
  --local path = uri .. param .. "=" .. uuid
  --stdnse.print_debug(1,"Queuing %s",path) 
	--all = http.pGet(host, port, path, options, nil, all)
  
	local results = http.pipeline(host, port, all)
  -- results == {response}
  
	-- Check for http.pipeline error
	if(results == nil) then
		stdnse.print_debug(1, "http-enum.nse: http.pipeline returned nil for " .. host[1])
		return stdnse.format_output(false, "http.pipeline returned nil")
	end

	for i, response in pairs(results) do
	
	  --print_response(response)
	
		-- Build the status code, if it isn't a 200
		local status = ""
		if(response.status ~= 200) then
  		stdnse.print_debug(1,"Got bas status code for arg %s ?",tested[i])
		end
		stdnse.print_debug(2,"Got result for status %s",response.status)

    --if i%1000 == 0 then
  	--	stdnse.print_debug(1,"Parsing results num %s",i)
    --end

    stdnse.print_debug(2,"Validating arg %s ",tested[i])
    if validate_p(response) then
      local uuid = tested[i]
      found[#found+1] = uuid
	    stdnse.print_debug(1,"Found " .. uuid) 
    end
  end

  local resultsstr ='Tested:' .. #results .. "/" .. #tested
  resultsstr = resultsstr .. "\n  Found: " .. #found
	if #found > 0 then
    for i=1, #found do resultsstr = resultsstr .. "\n  " .. param .. ":" .. found[i] end	    
  end


	return stdnse.format_output(true, resultsstr)
  	
end











portrule = shortport.port_or_service({80,443}, {"http","https"})

action = function(host, port)

  --local tstart = stdnse.clock_ms()

  local hostname = "localhost"
  local method = 'GET'
  local uri = '/'
  local arg = 'id'
  local limit = 100

	-- Get the base hostname, if in argument
	if(nmap.registry.args.hostname ~= nil) then
		--if(type(nmap.registry.args.path) == 'table') then
		--	paths = nmap.registry.args.path
		--else
		hostname = nmap.registry.args.hostname
	end
	if(nmap.registry.args.method ~= nil) then
		method = nmap.registry.args.method
	end
	if(nmap.registry.args.uri ~= nil) then
		uri = nmap.registry.args.uri
	end
	if(nmap.registry.args.arg ~= nil) then
		arg = nmap.registry.args.arg
	end
	if(nmap.registry.args.limit ~= nil) then
		limit = nmap.registry.args.limit
	end
  stdnse.print_debug(2,"Hostname is  " .. hostname) 
  stdnse.print_debug(2,"Method is " .. method) 
  stdnse.print_debug(2,"%s URI is %s",method, uri) 
  stdnse.print_debug(2,"param name is " .. arg) 
  stdnse.print_debug(2,"LIMIT =  " .. limit) 

  return brute_param_pipeline(host,port,hostname,method,uri,arg,limit)
	  
end
