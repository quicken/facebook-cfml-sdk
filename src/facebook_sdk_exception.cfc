<cfcomponent output="false" hint="Thrown when an API call returns an exception.">
	<cfscript>
	code = 0;
	msg = '';

	/* The result from the API server that represents the exception information. */
	result = structNew();
	</cfscript>

	<cffunction name="init" access="package" returntype="any">
		<cfargument name="result" required="true" type="struct">

		<cfset variables.result = arguments.result>

		<cfset code = 0>
		<cfset msg = ''>

		<cfif structIsEmpty(variables.result)>
			<cfreturn this>
		</cfif>

		<cfif structKeyExists(variables.result,'error_code')>
			<cfset code = variables.result['error_code']>
		<cfelse>
			<cfset code = 0>
		</cfif>

		<cfif structKeyExists(variables.result,'error')>
			<cfset msg = variables.result['error']['message']>
		<cfelse>
			<cfset msg = variables.result['error_msg']>
		</cfif>

		<cfreturn this>
	</cffunction>

	<cffunction name="getResult" access="public" returntype="struct" hint="Return the associated result object returned by the API server.">
		<cfreturn result>
	</cffunction>

	<cffunction name="getCode" access="public" returntype="numeric">
		<cfreturn code>
	</cffunction>

	<cffunction name="getMsg" access="public" returntype="string">
		<cfreturn msg>
	</cffunction>

	<cffunction name="getType" access="public" returntype="string" hint="Returns the associated type for the error. This will default to 'Exception' when a type is not available.">
		<cfif structKeyExists(variables.result,'error') AND structKeyExists(variables.result['error'],'type')>
			<cfreturn variables.result['error']['type']>
		</cfif>
		<cfreturn "Exception">
	</cffunction>

	<cffunction name="_toString" access="public" returntype="string" hint="To make debugging easier. Returns the string representation of the error">
		<cfset var tmp = getType() & ":">

		<cfif code NEQ 0>
			<cfset tmp = tmp & code & ":">
		</cfif>

		<cfset tmp = tmp & msg>

		<cfreturn tmp>
	</cffunction>
</cfcomponent>