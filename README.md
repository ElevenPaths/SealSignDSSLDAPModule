# SealSign - SealSignDSSLDAPModule

HTTP LDAP Authentication module for SealSign

## Overview

Once registered in a Web App, the HTTP module will capture all requests and check the authentication header for basic credentials. If present, it will authenticate the credentials against the LDAP configured. If not, a 401 response will be sent back to client. The authenticated account will be added to the IIS security context and WCF context through PrimaryIdentity for further processing.

## Use

* Add DLL assembly to bin directory of WCF application (f.e. c:\inetpub\wwwroot\sealsigndssservice\bin)
* Add LDAP bind path as an App Setting:
    * LDAPServer: Server LDAP path
    * LDAPServiceUser: Server LDAP service user, used to find the DN 
    * LDAPServicePassword:  Server LDAP service password
    * LDAPLogFile: (Optional) Log file path

    <appSettings>
        <add key="LDAPServer" value="LDAP://dc.domain.local"/>
        <add key="LDAPServiceUser" value="username@domain.local"/>
        <add key="LDAPServicePassword" value="password"/>
        <add key="LDAPFilter" value="(sAMAccountName={0})"/>
        <add key="LDAPLogFile" value="c:\temp\ldap.log"/>
    </appSettings>

* Register the HTTP module in web.config:

    <system.webServer>
        <validation validateIntegratedModeConfiguration="false" />
        <modules>
            <add name="LDAPHttpModule" type="SealSignDSSLibrary.LDAPHttpModule, SealSignDSSLDAPModule"/>

* Register the authorization module in web.config:

    <behaviors>
        <serviceBehaviors>
            <behavior name="LDAPTest.Service1Behavior">
                <serviceMetadata httpGetEnabled="true" />
                <serviceDebug includeExceptionDetailInFaults="false" />
                <serviceAuthorization>
                    <authorizationPolicies>
                        <add policyType="SealSignDSSLibrary.HttpContextAuthorizationPolicy, SealSignDSSLDAPModule" />
                    </authorizationPolicies>
                </serviceAuthorization>
            </behavior>
        </serviceBehaviors>
    </behaviors>
    <serviceHostingEnvironment aspNetCompatibilityEnabled="true" />
</system.serviceModel>
