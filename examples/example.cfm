<cfoutput>
<h2>Make sure you view the page from the domain that you registered with facebook!</h2>
<hr>
</cfoutput>

<cfscript>
APP_ID = '';// Your Application ID.
SECRET = '';// Your Facebook Secret.
</cfscript>

<cfset objFb = createObject('component','facebook_sdk').init(appId=APP_ID,secret=SECRET,useCookie=true,baseDomain="")>

<!--- ######################################################## --->
<!--- Show login url and request extended permissions. --->
<cfset param = structNew()>
<cfset param['req_perms'] = "email,read_stream,publish_stream">
<cfset loginUrl = objFb.getLoginUrl(param)>
<cfoutput><a href="#loginUrl#">Connect with Facebook</a><br></cfoutput>
<!--- ######################################################## --->



<!--- ######################################################## --->
<!--- Call the Graph API. --->
<cfset uid = 0>
<cfset fbme = "">

<cfset fbSession = objFb.getSession()>

<cfif NOT structIsEmpty(fbSession)>
	<cfset uid = objFb.getUser()>
	<cfset fbme = objFb.api('/me')>
</cfif>

<cfoutput>
	<h3>Called the Graph API</h3>
	UID:#uid#<br>
	<cfdump label="fbme" var="#fbme#">
</cfoutput>
<!--- ######################################################## --->




<!--- ######################################################## --->
<!--- Call the Legacy API. --->
<cfset userInfo = "">

<cfset fbSession = objFb.getSession()>

<cfif NOT structIsEmpty(fbSession)>
	<cfset param = structNew()>
	<cfset param['method'] = "users.getinfo">
	<cfset param['uids'] = uid>
	<cfset param['fields'] = "name,current_location,profile_url">
	<cfset param['callback'] = "">

	<cfset userInfo = objFb.api(param)>
</cfif>

<cfoutput>
	<h3>Called the legacy API</h3>
	<cfdump label="userInfo" var="#userInfo#">
</cfoutput>
<!--- ######################################################## --->


<!--- ######################################################## --->
<!--- Update status with Graph API. --->
<cfset statusUpdate = "">

<cfset fbSession = objFb.getSession()>

<cfif NOT structIsEmpty(fbSession)>
	<cfset param = structNew()>
	<cfset param['message'] = "Testing facebook API. It Works!">
	<cfset param['cb'] = "">
	<cfset statusUpdate = objFb.api('/me/feed',param,'post')>
</cfif>

<cfoutput>
	<h3>Update status with Graph API.</h3>
	<cfdump label="statusUpdate" var="#statusUpdate#">
</cfoutput>
<!--- ######################################################## --->




<!--- ######################################################## --->
<!--- Using FQL Query. --->
<cfset fqlResult = "">

<cfset fbSession = objFb.getSession()>

<cfif NOT structIsEmpty(fbSession)>
	<cfset fql = "select name, hometown_location, sex, pic_square from user where uid=#objFb.getUser()#">
	<cfset param = structNew()>
	<cfset param['method'] = "fql.query">
	<cfset param['query'] = fql>
	<cfset param['callback'] = ''>

	<cfset fqlResult = objFb.api(param)>
</cfif>

<cfoutput>
	<h3> Using FQL Query.</h3>
	<cfdump label="fqlResult" var="#fqlResult#">
</cfoutput>
<!--- ######################################################## --->