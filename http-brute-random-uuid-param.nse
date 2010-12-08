description = [[

This nmap NSE script is a learning test tool.

It's aim is to try 'brute-force' attempts on guessing valid values for a UUID parameter.
Quoting Wikipedia http://en.wikipedia.org/wiki/Universally_unique_identifier#Random_UUID_probability_of_duplicates :

  "In other words, only after generating 1 billion UUIDs every second for the next 100 years, 
  the probability of creating just one duplicate would be about 50%."

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
-- METHOD='HEAD'
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
-- @args http-brute-random-uuid-param.hostname sets the host header in case of virtual 
--       hosting
-- @args http-brute-random-uuid-param.method sets the HTTP method
-- @args http-brute-random-uuid-param.uri sets the uri path without the param, 
--       but with other param if needed (? included)
-- @args http-brute-random-uuid-param.param sets the parameter name
-- @args http-brute-random-uuid-param.limit sets the max number of guesses


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


-- generates a type 4 UUID
local get_uuid = function()
  return uuid.new()
end


--
-- Validates the responses.
--   Here we just check for the 'expires' headers.
--   The test could be extended or simplified for status code, or other fields...
--
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

  return true
  
end


--
-- use the http lib and the pipeline function to queue as many request in as few 
--  SYN as possible.
-- 
--  2k:  Completed NSE at 22:51, 158.50s elapsed
--
--
--
local brute_param_pipeline = function(host,port,hostname,method,uri,param,limit)
  local tested = {}
  local found = {}
  local all = {}
  local uuids = {}
  local options = {
    header = {
      -- set Host: header
      Host = hostname,
      -- ncrack should be better but.. there's no LUA support ... sad sad sad...
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
    all = http.pipeline_add(path,options,all,method)

  end

  
  --local results = http.pipeline(host, port, all)
  local results = http.pipeline_go(host, port, all)
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
      stdnse.print_debug(1,"Got bas status code for param %s ?",tested[i])
    end
    stdnse.print_debug(2,"Got result for status %s",response.status)

    --if i%1000 == 0 then
    --  stdnse.print_debug(1,"Parsing results num %s",i)
    --end

    stdnse.print_debug(2,"Validating param %s ",tested[i])
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
  local method = 'HEAD'
  local uri = '/'
  local param = 'id'
  local limit = 100

  -- Get the base hostname, if in argument
  if(nmap.registry.args.hostname ~= nil) then
    --if(type(nmap.registry.args.path) == 'table') then
    --  paths = nmap.registry.args.path
    --else
    hostname = nmap.registry.args.hostname
  end
  if(nmap.registry.args.method ~= nil) then
    method = nmap.registry.args.method
  end
  if(nmap.registry.args.uri ~= nil) then
    uri = nmap.registry.args.uri
  end
  if(nmap.registry.args.param ~= nil) then
    param = nmap.registry.args.param
  end
  if(nmap.registry.args.limit ~= nil) then
    limit = nmap.registry.args.limit
  end
  stdnse.print_debug(2,"Hostname is  " .. hostname) 
  stdnse.print_debug(2,"Method is " .. method) 
  stdnse.print_debug(2,"%s URI is %s",method, uri) 
  stdnse.print_debug(2,"param name is " .. param) 
  stdnse.print_debug(2,"LIMIT =  " .. limit) 

  return brute_param_pipeline(host,port,hostname,method,uri,param,limit)
    
end

