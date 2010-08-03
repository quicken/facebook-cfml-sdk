<cfcomponent output="false" hint="cfml port of the php facebook sdk. http://github.com/facebook/php-sdk">
	<!---
	Author: Marcel Scherzer.
	Created: 2010-07-30

	Contact: www.bikemoments.com
	 --->

	<cfset this.DEBUG = false><!--- Set to true to log API calls to the fb_api.log file. --->
	<cfset this.exception = createObject('component','facebook_sdk_exception').init(structNew())>

	<cfscript>
	/* Version. */
	VERSION = '2.0.6';

	/* Default options for curl. We use cfhttp but keep the parameter names from the php implementation. */
	CURL_OPTS = structNew();
	CURL_OPTS.CURLOPT_CONNECTTIMEOUT = 10;
	// CURL_OPTS.CURLOPT_RETURNTRANSFER = true; not needed in cfml implementation.
	// CURL_OPTS.CURLOPT_TIMEOUT = 60; not needed in cfml implementation.
	CURL_OPTS.CURLOPT_USERAGENT = 'facebook-cfm-2.0';

	/* List of query parameters that get automatically dropped when rebuilding the current URL. */
	DROP_QUERY_PARAMS = arrayNew(1);
	DROP_QUERY_PARAMS[1] = 'session';
	DROP_QUERY_PARAMS[2] = 'signed_request';

	/* Maps aliases to Facebook domains */
	DOMAIN_MAP = structNew();
	DOMAIN_MAP.api = 'https://api.facebook.com/';
	DOMAIN_MAP.api_read = 'https://api-read.facebook.com/';
	DOMAIN_MAP.graph = 'https://graph.facebook.com/';
	DOMAIN_MAP.www = 'https://www.facebook.com/';

	/* The Application ID. */
	appId = "";

	/* The Application API Secret. */
	apiSecret = "";

	/* The active user session, if one is available. */
	fbSession = structNew();

	/* The data from the signed_request token. */
	signedRequest = '';

	/* Indicates that we already loaded the session as best as we could. */
	sessionLoaded = false;

	/* Indicates if Cookie support should be enabled. */
	cookieSupport = false;

	/* Base domain for the Cookie. */
	baseDomain = '';
	</cfscript>

	<cffunction name="init" access="public" returntype="any">
		<cfargument name="appId" required="true" type="string">
		<cfargument name="secret" required="true" type="string">
		<cfargument name="useCookie" required="false" type="string" default="true">
		<cfargument name="baseDomain" required="false" type="string" default="">

		<cfset setAppID(arguments.appID)>
		<cfset setApiSecret(arguments.secret)>
		<cfset setCookieSupport(arguments.useCookie)>
		<cfset setBaseDomain(arguments.baseDomain)>

		<cfreturn this>
	</cffunction>

	<cffunction name="setAppId" access="private" returntype="void" hint="Set the Application ID.">
		<cfargument name="value" required="true" type="string">
		<cfset appId = arguments.value>
		<cfreturn>
	</cffunction>

	<cffunction name="getAppId" access="public" returntype="string" hint="Get the Application ID.">
		<cfreturn appId>
	</cffunction>

	<cffunction name="setApiSecret" access="private" returntype="void" hint="Set the API Secret.">
		<cfargument name="value" required="true" type="string">
		<cfset apiSecret = arguments.value>
		<cfreturn>
	</cffunction>

	<cffunction name="getApiSecret" access="public" returntype="string" hint="Get the API Secret.">
		<cfreturn apiSecret>
	</cffunction>

	<cffunction name="setCookieSupport" access="private" returntype="void" hint="Set the Cookie Support status.">
		<cfargument name="value" required="true" type="boolean">
		<cfset cookieSupport = arguments.value>
		<cfreturn>
	</cffunction>

	<cffunction name="useCookieSupport" access="private" returntype="boolean" hint="Get the Cookie Support status.">
		<cfreturn cookieSupport>
	</cffunction>

	<cffunction name="setBaseDomain" access="private" returntype="void" hint="Set the base domain for the Cookie.">
		<cfargument name="value" required="true" type="string">
		<cfset baseDomain = arguments.value>
		<cfreturn>
	</cffunction>

	<cffunction name="getBaseDomain" access="public" returntype="string" hint="Get the base domain for the Cookie.">
		<cfreturn baseDomain>
	</cffunction>

	<cffunction name="getSignedRequest" access="public" returntype="string" hint="Get the data from a signed_request token.">
		<cfif variables.signedRequest EQ "">
			<cfif isDefined('URL.signedRequest')>
				<cfset variables.signedRequest = parseSignedRequest(URL.signedRequest)>
			</cfif>
			<cfif isDefined('FORM.signedRequest')>
				<cfset variables.signedRequest = parseSignedRequest(FORM.signedRequest)>
			</cfif>
		</cfif>

		<cfreturn variables.signedRequest>
	</cffunction>

	<cffunction name="setSession" access="public" returntype="void" hint="Set the Session.">
		<cfargument name="fbSession" required="false" type="struct" hint="The session">
		<cfargument name="write_cookie" required="false" type="boolean" default="true" hint="indicate if a cookie should be written. This value is ignored if cookie support has been disabled.">

		<cfset variables.fbSession = duplicate(validateSessionObject(arguments.fbSession))>
		<cfset sessionLoaded = true>
		<cfif arguments.write_cookie>
			<cfset setCookieFromSession(variables.fbSession)>
		</cfif>

		<cfreturn>
	</cffunction>

	<cffunction name="getSession" access="public" returntype="struct" hint="Get the session object. This will automatically look for a signed session sent via the signed_request, Cookie or Query Parameters if needed.">
		<cfset var tmpSession = structNew()>
		<cfset var write_cookie = true>
		<cfset var signedRequest = "">
		<cfset var sessionString = "">
		<cfset var cookieName = "">

		<cfif sessionLoaded>
			<cfset tmpSession = fbSession>
		<cfelse>
			<!--- try loading session from signed_request in $_REQUEST --->
			<cfset signedRequest = getSignedRequest()>
			<cfif signedRequest NEQ "">
				<!--- sig is good, use the signedRequest --->
				<cfset tmpSession = createSessionFromSignedRequest(signedRequest)>
			</cfif>

			<!--- See if there is a session parameter defined in URL or FORM scope. --->
			<cfif isDefined('URL.session')>
				<cfset sessionString = URL.session>
			<cfelseif isDefined('FORM.session')>
				<cfset sessionString = FORM.session>
			<cfelse>
				<cfset sessionString = "">
			</cfif>

			<!--- Try loading session from URL or FORM scope. --->
			<cfif (structIsEmpty(tmpSession))		AND		(sessionString NEQ "")>
				<cfset tmpSession = deserializeJSON(sessionString)>
				<cfset tmpSession = validateSessionObject(tmpSession)>
			</cfif>

			<!--- Try loading session from cookie if necessary. --->
			<cfif (structIsEmpty(tmpSession))		AND		(useCookieSupport())>
				<cfset cookieName = getSessionCookieName()>
				<cfif structKeyExists(cookie,cookieName)>
					<cfset tmpSession = php_parse_str(cookie[cookieName])>
					<cfset tmpSession = validateSessionObject(tmpSession)>
					<cfset write_cookie = structIsEmpty(tmpSession)>
				</cfif>
			</cfif>

			<cfset setSession(tmpSession,write_cookie)>
		</cfif>

		<cfreturn tmpSession>
	</cffunction>

	<cffunction name="getUser" access="public" returntype="string" hint="Get the UID from the session.">
		<cfif NOT structKeyExists(fbSession,'uid')>
			<cfreturn "">
		</cfif>
		<cfreturn fbSession.uid>
	</cffunction>

	<cffunction name="getAccessToken" access="public" returntype="string" hint="Gets a OAuth access token.">
		<cfset var fbSession = getSession()>

		<!--- either user session signed, or app signed --->
		<cfif structKeyExists(fbSession,'access_token')>
			<cfreturn fbSession.access_token>
		</cfif>

		<cfreturn getAppId() & "|" & getApiSecret()>
	</cffunction>

	<cffunction name="getLoginUrl" access="public" returntype="string" hint="Get a Login URL for use with redirects. By default, full page redirect is assumed. If you are using the generated URL with a window.open() call in JavaScript, you can pass in display=popup as part of the params.">
		<cfargument name="params" required="false" type="struct" default="#structNew()#" hint="provide custom parameters">
		<cfset var currentUrl = getCurrentUrl()>

		<cfscript>
		structInsert(arguments.params,'api_key',getAppId(),true);
		if(NOT structKeyExists(arguments.params,'cancel_url')){
			structInsert(arguments.params,'cancel_url',currentUrl,true); // the url to go to after the user cancels
		}
		if(NOT structKeyExists(arguments.params,'display')){
			structInsert(arguments.params,'display','page',true); // can be "page" (default, full page) or "popup"
		}
		if(NOT structKeyExists(arguments.params,'fbconnect')){
			structInsert(arguments.params,'fbconnect',1,true);
		}
		if(NOT structKeyExists(arguments.params,'next')){
			structInsert(arguments.params,'next',currentUrl,true); // the url to go to after a successful login
		}
		structInsert(arguments.params,'return_session',1,true);
		structInsert(arguments.params,'session_version',3,true);
		structInsert(arguments.params,'v','1.0',true);
		</cfscript>

		<cfreturn getUrl('www','login.php',arguments.params)>
	</cffunction>

	<cffunction name="getLogoutUrl" returntype="string" hint="Get a Logout URL suitable for use with redirects.">
		<cfargument name="params" required="false" type="struct" default="#structNew()#" hint="provide custom parameters">

		<cfscript>
		if(NOT structKeyExists(arguments.params,'next')){
			structInsert(arguments.params,'next',getCurrentUrl(),true); //the url to go to after a successful logout
		}
		structInsert(arguments.params,'access_token',getAccessToken(),true);
		</cfscript>

		<cfreturn getUrl('www','logout.php',arguments.params)>
	</cffunction>

	<cffunction name="getLoginStatusUrl" returntype="string" hint="Get a login status URL to fetch the status from facebook.">
		<cfargument name="params" required="false" type="struct" default="#structNew()#" hint="provide custom parameters">

		<cfscript>
		structInsert(arguments.params,'api_key',getAppId(),true); //the url to go to after a successful logout
		structInsert(arguments.params,'no_session',getCurrentUrl(),true);
		structInsert(arguments.params,'no_user',getCurrentUrl(),true);
		structInsert(arguments.params,'ok_session',getCurrentUrl(),true);
		structInsert(arguments.params,'session_version',3,true);
		</cfscript>

		<cfreturn getUrl('www','extern/login_status.php',arguments.params)>
	</cffunction>

	<cffunction name="api" access="public" returntype="any" hint="Make an API call.">
		<cfargument name="value" type="any" required="true" hint="the path for graph calls or a struct for the old restserver api.">
		<cfargument name="params" type="struct" required="false" default="#structNew()#" hint="the API call parameters">
		<cfargument name="method" type="string" required="false" default="GET" hint="the http method (default 'GET')">

		<cfif isStruct(arguments.value)>
			<cfreturn _restserver(arguments.value)>
		</cfif>

		<cfreturn _graph(arguments.value,arguments.method,arguments.params)>
	</cffunction>

	<cffunction name="_restserver" access="private" returntype="any" hint="Invoke the old restserver.php endpoint.">
		<cfargument name="params" type="struct" required="false" default="#structNew()#" hint="method call object">

		<!--- generic application level parameters --->
		<cfset structInsert(arguments.params,'api_key',getAppId(),true)>
		<cfset structInsert(arguments.params,'format','json-strings',true)>

		<cfset result = deserializeJson(_oauthRequest(getApiUrl(arguments.params['method']),arguments.params))>

		<!--- Results are returned, errors are thrown --->
		<cfif isStruct(result) AND structKeyExists(result,'error_code')>
			<cfset fb_throw(result)>
		</cfif>

		<cfreturn result>
	</cffunction>

	<cffunction name="_graph" access="private" returntype="any" hint="Invoke the Graph API.">
		<cfargument name="path" type="string" required="true" hint="the path">
		<cfargument name="method" type="string" required="false" default="GET" hint="the http method (default 'GET')">
		<cfargument name="params" type="struct" required="false" default="#structNew()#" hint="the query/post data">

		<cfset var result = "">

		<cfset result = deserializeJson(_oauthRequest(getUrl('graph',arguments.path),arguments.params,arguments.method))>

		<!--- Results are returned, errors are thrown --->
		<cfif isStruct(result) AND structKeyExists(result,'error')>
			<!--- Within the PHP code the session is cleared here in the cfml port the fb_throw method handles that logic. --->
			<cfset fb_throw(result)>
		</cfif>

		<cfreturn result>
	</cffunction>

	<cffunction name="_oauthRequest" access="private" returntype="string" hint="Make a OAuth Request.">
		<cfargument name="uri" type="string" required="true" hint="the path">
		<cfargument name="params" type="struct" required="false" default="#structNew()#" hint="the query/post data">
		<cfargument name="method" type="string" required="false" default="GET" hint="The HTTP request method.">

		<cfset var key = "">

		<cfif NOT structKeyExists(arguments.params,'access_token')>
			<cfset structInsert(arguments.params,'access_token',getAccessToken())>
		</cfif>

		<!--- json_encode all params values that are not strings. --->
		<cfloop collection="#arguments.params#" item="key">
			<cfif NOT isSimpleValue(arguments.params[key])>
				<cfset arguments.params[key] = serializeJson(arguments.params[key])>
			</cfif>
		</cfloop>

		<cfreturn makeRequest(uri=arguments.uri,params=arguments.params,method=arguments.method)>
	</cffunction>

	<cffunction name="makeRequest" access="private" returntype="string" hint="Makes an HTTP request. This method can be overriden by subclasses if developers want to do fancier things to make a request.">
		<cfargument name="uri" type="string" required="true" hint="The URL to make the request to">
		<cfargument name="params" type="struct" required="false" default="#structNew()#" hint="The parameters to use for the POST body">
		<cfargument name="method" type="string" required="false" default="GET" hint="The HTTP request method.">

		<cfset var cfhttp = "">
		<cfset var key = "">
		<cfset var response = "">
		<cfset var exception = structNew()>
		<cfset var type = "">

		<cfif arguments.method EQ "GET">
			<cfset type = "URL">
		<cfelse>
			<cfset type = "FORMFIELD">
		</cfif>

		<cftry>
			<cfhttp url="#arguments.uri#" method="#arguments.method#" charset="utf-8" useragent="#CURL_OPTS.CURLOPT_USERAGENT#" timeout="#CURL_OPTS.CURLOPT_CONNECTTIMEOUT#" throwonerror="true">
				<cfloop collection="#arguments.params#" item="key">
					<cfhttpparam type="#type#" name="#key#" value="#arguments.params[key]#">
				</cfloop>
			</cfhttp>

			<cfcatch type="any">
				<cfif this.DEBUG>
					<cflog file="debug" type="warning" text="facebook_makeRequest|#arguments.uri#|#serializeJSON(arguments.params)#">
				</cfif>

				<cfif isDefined('cfhttp.statusCode')>
					<cfset exception.error_code = cfhttp.statusCode>
				<cfelse>
					<cfset exception.error_code = -1>
				</cfif>
				<cfset exception.error = structNew()>
				<cfset exception.error.message = cfcatch.message>
				<cfset exception.error.type = 'makeRequestException'>
				<cfset fb_throw(exception)>
			</cfcatch>
		</cftry>


		<cfif this.DEBUG>
			<cflog file="debug" type="information" text="facebook_makeRequest|#arguments.uri#|#serializeJSON(arguments.params)#|response:#cfhttp.FileContent#">
		</cfif>

		<cfset response = trim(cfhttp.fileContent)>

		<cfreturn response>
	</cffunction>

	<cffunction name="getSessionCookieName" access="private" returntype="string" hint="The name of the Cookie that contains the session.">
		<cfreturn "fbs_" & getAppId()>
	</cffunction>

	<cffunction name="setCookieFromSession" access="private" returntype="void" hint="Set a JS Cookie based on the _passed in_ session. It does not use the currently stored session -- you need to explicitly pass it in.">
		<cfargument name="fbSession" required="false" type="struct" default="#structNew()#">

		<cfset var cookieName = getSessionCookieName()>
		<cfset var value = 'deleted'>
		<cfset var expires = php_time() - 3600>
		<cfset var domain = getBaseDomain()>

		<cfif NOT useCookieSupport()>
			<cfreturn>
		</cfif>

		<cfif NOT structIsEmpty(arguments.fbSession)>
			<cfset value = php_http_build_query(arguments.fbSession)>

			<cfif structKeyExists(arguments.fbSession,'base_domain')>
				<cfset domain = arguments.fbSession['base_domain']>
			</cfif>

			<cfset expires = arguments.fbSession['expires']>
		</cfif>

		<!--- prepend dot if a domain is found --->
		<cfif domain NEQ "">
			<cfset domain = "." & domain>
		</cfif>

		<!--- if an existing cookie is not set, we dont need to delete it --->
		<cfif value EQ "deleted" AND NOT structKeyExists(cookie,cookieName)>
			<cfreturn>
		</cfif>

		<cfcookie name="#cookieName#" value="#value#" expires="#expires#" domain="#domain#">

		<cfreturn>
	</cffunction>

	<cffunction name="validateSessionObject" access="private" returntype="struct" hint="Validates a session_version=3 style session object.">
		<cfargument name="fbSession" required="true" type="struct" hint="the session object">
		<cfset var session_without_sig = structNew()>
		<cfset var expected_sig = "">


		<!--- make sure some essential fields exist --->
		<cfif structKeyExists(arguments.fbSession,'uid') AND structKeyExists(arguments.fbSession,'access_token') AND structKeyExists(arguments.fbSession,'sig')>

			<cfset session_without_sig = duplicate(arguments.fbSession)>
			<cfset structDelete(session_without_sig,'sig',false)>

			<cfset expected_sig = generateSignature(session_without_sig,getApiSecret())>

			<cfif expected_sig NEQ arguments.fbSession.sig>
				<cfset arguments.fbSession = structNew()>
			</cfif>
		<cfelse>
			<cfset arguments.fbSession = structNew()>
		</cfif>

		<cfreturn arguments.fbSession>
	</cffunction>

	<cffunction name="createSessionFromSignedRequest" access="private" returntype="struct" hint="Returns something that looks like our JS session object from the signed token's data.">
		<cfargument name="data" required="true" type="struct" hint="The output of getSignedRequest">

		<cfset var fbSession = structNew()>

		<cfif NOT structKeyExists(arguments.data,'oauth_token')>
			<cfreturn structNew()>
		</cfif>

		<cfset fbSession.uid = arguments.data['user_id']>
		<cfset fbSession.access_token = arguments.data['oauth_token']>
		<cfset fbSession.expires = arguments.data['expires']>

		<!--- put a real sig, so that validateSignature works --->
		<cfset fbSession.sig = generateSignature(fbSession,getApiSecret())>

		<cfreturn fbSession>
	</cffunction>

	<cffunction name="parseSignedRequest" access="private" returntype="struct" hint="Parses a signed_request and validates the signature.">
		<cfargument name="signed_request" required="true" type="string" hint="A signed token.">

		<cfset var encoded_sig = getToken(arguments.signed_request,1,'.')>
		<cfset var payload = getToken(arguments.signed_request,2,'.')>
		<cfset var sig = "">
		<cfset var data = "">
		<cfset var expected_sig = "">

		<!--- decode the data --->
		<cfset sig = base64UrlDecode(encoded_sig)>
		<cfset data = base64UrlDecode(payload)>

		<cfif ucase(data['algorithm'] NEQ "HMAC-SHA256")>
			<cfset errorLog("Unknown algorithm. Expected HMAC-SHA256.")>
			<cfreturn structNew()>
		</cfif>

		<!--- check sig --->
		<cfset expected_sig = hash(payload,"SHA-256","utf-8")>
		<cfif sig NEQ expected_sig>
			<cfset errorLog("Bad Signed JSON signature!")>
			<cfreturn structNew()>
		</cfif>

		<cfreturn data>
	</cffunction>

	<cffunction name="getApiUrl" access="private" returntype="string" hint="Build the URL for api given parameters.">
		<cfargument name="method" required="true" type="string" hint="The method name.">
		<cfset var READ_ONLY_CALLS = structNew()>
		<cfset var name = 'api'>

		<cfscript>
		READ_ONLY_CALLS.admin = structNew();
    READ_ONLY_CALLS.admin.getappproperties = 1;
		READ_ONLY_CALLS.admin.getbannedusers = 1;
		READ_ONLY_CALLS.admin.getlivestreamvialink = 1;
		READ_ONLY_CALLS.admin.getmetrics = 1;
		READ_ONLY_CALLS.admin.getrestrictioninfo = 1;

		READ_ONLY_CALLS.application = structNew();
		READ_ONLY_CALLS.application.getpublicinfo = 1;

		READ_ONLY_CALLS.auth = structNew();
		READ_ONLY_CALLS.auth.getapppublickey = 1;
		READ_ONLY_CALLS.auth.getsession = 1;
		READ_ONLY_CALLS.auth.getsignedpublicsessiondata = 1;

		READ_ONLY_CALLS.comments = structNew();
		READ_ONLY_CALLS.comments.get = 1;

		READ_ONLY_CALLS.connect = structNew();
		READ_ONLY_CALLS.connect.getunconnectedfriendscount = 1;

		READ_ONLY_CALLS.dashboard = structNew();
		READ_ONLY_CALLS.dashboard.getactivity = 1;
		READ_ONLY_CALLS.dashboard.getcount = 1;
		READ_ONLY_CALLS.dashboard.getglobalnews = 1;
		READ_ONLY_CALLS.dashboard.getnews = 1;
		READ_ONLY_CALLS.dashboard.multigetcount = 1;
		READ_ONLY_CALLS.dashboard.multigetnews = 1;

		READ_ONLY_CALLS.data = structNew();
		READ_ONLY_CALLS.data.getcookies = 1;

		READ_ONLY_CALLS.events = structNew();
		READ_ONLY_CALLS.events.get = 1;
		READ_ONLY_CALLS.events.getmembers = 1;

		READ_ONLY_CALLS.fbml = structNew();
		READ_ONLY_CALLS.fbml.getcustomtags = 1;

		READ_ONLY_CALLS.feed = structNew();
		READ_ONLY_CALLS.feed.getappfriendstories = 1;
		READ_ONLY_CALLS.feed.getregisteredtemplatebundlebyid = 1;
		READ_ONLY_CALLS.feed.getregisteredtemplatebundles = 1;

		READ_ONLY_CALLS.fql = structNew();
		READ_ONLY_CALLS.fql.multiquery = 1;
		READ_ONLY_CALLS.fql.query = 1;

		READ_ONLY_CALLS.friends = structNew();
		READ_ONLY_CALLS.friends.arefriends = 1;
		READ_ONLY_CALLS.friends.get = 1;
		READ_ONLY_CALLS.friends.getappusers = 1;
		READ_ONLY_CALLS.friends.getlists = 1;
		READ_ONLY_CALLS.friends.getmutualfriends = 1;

		READ_ONLY_CALLS.gifts = structNew();
		READ_ONLY_CALLS.gifts.get = 1;

		READ_ONLY_CALLS.groups = structNew();
		READ_ONLY_CALLS.groups.get = 1;
		READ_ONLY_CALLS.groups.getmembers = 1;

		READ_ONLY_CALLS.intl = structNew();
		READ_ONLY_CALLS.intl.gettranslations = 1;

		READ_ONLY_CALLS.links = structNew();
		READ_ONLY_CALLS.links.get = 1;

		READ_ONLY_CALLS.notes = structNew();
		READ_ONLY_CALLS.notes.get = 1;

		READ_ONLY_CALLS.notifications = structNew();
		READ_ONLY_CALLS.notifications.get = 1;

		READ_ONLY_CALLS.page = structNew();
		READ_ONLY_CALLS.pages.getinfo = 1;
		READ_ONLY_CALLS.pages.isadmin = 1;
		READ_ONLY_CALLS.pages.isappadded = 1;
		READ_ONLY_CALLS.pages.isfan = 1;

		READ_ONLY_CALLS.permissions = structNew();
		READ_ONLY_CALLS.permissions.checkavailableapiaccess = 1;
		READ_ONLY_CALLS.permissions.checkgrantedapiaccess = 1;

		READ_ONLY_CALLS.photos = structNew();
		READ_ONLY_CALLS.photos.get = 1;
		READ_ONLY_CALLS.photos.getalbums = 1;
		READ_ONLY_CALLS.photos.gettags = 1;

		READ_ONLY_CALLS.profile = structNew();
		READ_ONLY_CALLS.profile.getinfo = 1;
		READ_ONLY_CALLS.profile.getinfooptions = 1;

		READ_ONLY_CALLS.stream = structNew();
		READ_ONLY_CALLS.stream.get = 1;
		READ_ONLY_CALLS.stream.getcomments = 1;
		READ_ONLY_CALLS.stream.getfilters = 1;

		READ_ONLY_CALLS.users = structNew();
		READ_ONLY_CALLS.users.getinfo = 1;
		READ_ONLY_CALLS.users.getloggedinuser = 1;
		READ_ONLY_CALLS.users.getstandardinfo = 1;
		READ_ONLY_CALLS.users.hasapppermission = 1;
		READ_ONLY_CALLS.users.isappuser = 1;
		READ_ONLY_CALLS.users.isverified = 1;

		READ_ONLY_CALLS.video = structNew();
		READ_ONLY_CALLS.video.getuploadlimits = 1;
		</cfscript>

		<cfif structKeyExists(READ_ONLY_CALLS,arguments.method)>
			<cfset name = "api_read">
		</cfif>

		<cfreturn getUrl(name,'restserver.php')>
	</cffunction>

	<cffunction name="getUrl" access="private" returntype="string" hint="Build the URL for given domain alias, path and parameters.">
		<cfargument name="name" type="string" required="true" hint="The name of the domain">
		<cfargument name="path" type="string" required="false" default="" hint="path (without a leading slash)">
		<cfargument name="params" type="struct" required="false" default="#structNew()#" hint="struct of query parameters">

		<cfset var uri = DOMAIN_MAP[arguments.name]>

		<cfif arguments.path NEQ "">
			<cfif left(arguments.path,1) EQ "/">
				<cfset arguments.path = replace(arguments.path,'/','','one')>
			</cfif>
			<cfset uri = uri & arguments.path>
		</cfif>

		<cfif NOT structIsEmpty(arguments.params)>
			<cfset uri = uri & "?" & php_http_build_query(arguments.params)>
		</cfif>

		<cfreturn uri>
	</cffunction>

	<cffunction name="getCurrentUrl" access="private" returntype="string" hint="Returns the Current URL, stripping it of known FB parameters that should not persist.">
		<cfset var protocol = "">
		<cfset var currentUrl = "">
		<cfset var i = "">

		<cfif (structKeyExists(CGI,'HTTPS')) 	AND	 (CGI.HTTPS EQ "on")>
			<cfset protocol = "https://">
		<cfelse>
			<cfset protocol = "http://">
		</cfif>

		<cfset currentUrl = protocol & CGI.HTTP_X_FORWARDED_HOST & CGI.SCRIPT_NAME>

		<!--- Drop known fb params --->
		<cfset params = php_parse_str(CGI.QUERY_STRING)>
		<cfloop from="1" to="#arrayLen(DROP_QUERY_PARAMS)#" index="i">
			<cfset structDelete(params,DROP_QUERY_PARAMS[i],false)>
		</cfloop>

		<cfif NOT structIsEmpty(params)>
			<cfset currentUrl = currentUrl & "?" & php_http_build_query(params)>
		</cfif>

		<!--- use port if non default --->
		<!--- The HTTP_X_FORWARDED_HOST parameter already includes the port. --->

		<cfreturn currentUrl>
	</cffunction>

	<cffunction name="generateSignature" access="private" returntype="string" hint="Generate a signature for the given params and secret.">
		<cfargument name="params" type="struct" required="false" default="#structNew()#" hint="the parameters to sign">
		<cfargument name="secret" type="string" required="false" default="#structNew()#" hint="secret the secret to sign with">
		<cfset var base_string = ''>
		<cfset var sortOrder = "">
		<cfset var i = 0>

		<!--- work with sorted data --->
		<cfset sortOrder = structKeyArray(arguments.params)>
		<cfset arraySort(sortOrder,"text",'asc')>

		<!--- generate the base string --->
		<cfloop from="1" to="#arrayLen(sortOrder)#" index="i">
			<cfset base_string = base_string & sortOrder[i] & "=" & arguments.params[sortOrder[i]]>
		</cfloop>
		<cfset base_string = base_string & arguments.secret>

		<cfreturn lcase(hash(base_string,"MD5","utf-8"))>
	</cffunction>

	<cffunction name="errorLog" access="private" hint="Prints to the error log">
		<cfargument name="msg" type="string" required="true" hint="log message">

		<cfreturn>
	</cffunction>

	<cffunction name="base64UrlDecode" access="private" hint="Base64 encoding that doesn't need to be urlencode()ed.">
		<cfargument name="input" type="string" required="true" hint="base64UrlEncodeded string">
		<cfreturn binaryDecode(replaceNoCase(arguments.input,'-_','+/','all'),"base64")>
	</cffunction>

	<cffunction name="fb_throw" access="private" returntype="void" hint="Custom way to handle throwing exceptions in this component.">
		<cfargument name="error" required="true" type="struct">
		<cfset this.exception.init(arguments.error)>

		<cfif this.exception.getType() EQ "OAuthException">
			<cfset setSession(structNew())>
		</cfif>

		<cfthrow type="facebook" errorcode="#this.exception.getCode()#" extendedinfo="#this.exception.getMsg()#">

		<cfreturn>
	</cffunction>

<!--- ###################################### --->
<!--- Simulate PHP functions needed to match the original PHP code as close as possible. --->
	<cffunction name="php_parse_str" access="private" returntype="struct" hint="simulate PHP parse_str function.">
		<cfargument name="value" required="true" type="string">
		<cfset var str = structNew()>
		<cfset var pair = "">
		<cfset var name = "">

		<cfloop list="#arguments.value#" index="pair" delimiters="&">
			<cfset name = getToken(pair,1,'=')>
			<cfif name NEQ "">
				<cfset structInsert(str,name,getToken(pair,2,'='),true)>
			</cfif>
		</cfloop>

		<cfreturn str>
	</cffunction>

	<cffunction name="php_http_build_query" access="private" returntype="string" hint="simulate PHP http_build_query function.">
		<cfargument name="str" required="true" type="struct">
		<cfset var queryString = "">
		<cfset var pair = "">
		<cfset var name = "">

		<cfloop collection="#arguments.str#" item="name">
			<cfset pair = name & "=" & arguments.str[name]>
			<cfset queryString = listAppend(queryString,pair,"&")>
		</cfloop>

		<cfreturn queryString>
	</cffunction>

	<cffunction name="php_time" access="private" returntype="numeric" hint="Returns the current time as a Unix timestamp">
		<cfreturn dateDiff("s", createDate(1970,1,1), Now()) />
	</cffunction>
<!--- ###################################### --->
</cfcomponent>