using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.Text;
using System.Web;
using System.Security.Principal;
using System.Threading;
using System.DirectoryServices;
using System.Configuration;
using System.IO;

namespace SealSignDSSLibrary
{
    public class LDAPHttpModule : IHttpModule
    {
        private const string Realm = "SealSignDSS";

        // web.config sample
        //<appSettings>
        //    <add key="LDAPServer" value="LDAP://dc.domain.local"/>
        //    <add key="LDAPServiceUser" value="username@domain.local"/>
        //    <add key="LDAPServicePassword" value="password"/>
        //    <add key="LDAPFilter" value="(sAMAccountName={0})"/>
        //    <add key="LDAPUserName" value="distinguishedName"/>
        //    <add key="LDAPLogFile" value="c:\temp\ldap.log"/>
        //</appSettings>

        public void Init(HttpApplication context)
        {
            context.BeginRequest += OnApplicationBeginRequest;
            context.AuthenticateRequest += OnApplicationAuthenticateRequest;
            context.EndRequest += OnApplicationEndRequest;
        }

        private static void SetPrincipal(IPrincipal principal)
        {
            Thread.CurrentPrincipal = principal;

            if (HttpContext.Current != null)
            {
                HttpContext.Current.User = principal;
            }
        }

        private static bool CheckPassword(string userName, string password)
        {
            try
            {
                DirectoryEntry serviceEntry = new DirectoryEntry(ConfigurationManager.AppSettings["LDAPServer"].ToString(),
                    ConfigurationManager.AppSettings["LDAPServiceUser"].ToString(),
                    ConfigurationManager.AppSettings["LDAPServicePassword"].ToString(),
                    AuthenticationTypes.ServerBind | AuthenticationTypes.FastBind);

                DirectorySearcher search = new DirectorySearcher(serviceEntry);

                search.PropertiesToLoad.Add(ConfigurationManager.AppSettings["LDAPUserName"].ToString());
                search.PropertiesToLoad.Add("cn");
                search.Filter = string.Format(ConfigurationManager.AppSettings["LDAPFilter"].ToString(), userName);
                
                SearchResult result = search.FindOne();

                if (result != null && !string.IsNullOrEmpty(result.Path))
                {
                    Uri ldapUri = new Uri(result.Path);
                    
                    string distinguishedName = null;

                    if (ldapUri.PathAndQuery[0] == '/')
                    {
                        distinguishedName = ldapUri.PathAndQuery.Substring(1);
                    }

                    distinguishedName = Uri.UnescapeDataString(distinguishedName);
                    
                    DirectoryEntry userEntry = new DirectoryEntry(ConfigurationManager.AppSettings["LDAPServer"].ToString(),
                        distinguishedName,
                        password,
                        AuthenticationTypes.ServerBind | AuthenticationTypes.FastBind);

                    // Forzamos el bind accediendo a algun objeto
                    Object testConnection = userEntry.NativeObject;

                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                try
                {
                    if (string.IsNullOrEmpty(ConfigurationManager.AppSettings["LDAPLogFile"]) == false)
                    {
                        StreamWriter sw = new StreamWriter(ConfigurationManager.AppSettings["LDAPLogFile"].ToString(), true);

                        if (ex.InnerException != null)
                        {
                            sw.Write("Inner Exception Type: ");
                            sw.WriteLine(ex.InnerException.GetType().ToString());
                            sw.Write("Inner Exception: ");
                            sw.WriteLine(ex.InnerException.Message);
                            sw.Write("Inner Source: ");
                            sw.WriteLine(ex.InnerException.Source);
                            if (ex.InnerException.StackTrace != null)
                            {
                                sw.WriteLine("Inner Stack Trace: ");
                                sw.WriteLine(ex.InnerException.StackTrace);
                            }
                        }

                        sw.Write("Exception Type: ");
                        sw.WriteLine(ex.GetType().ToString());
                        sw.WriteLine("Exception: " + ex.Message);
                        sw.WriteLine("Source: " + ex.Source);
                        sw.WriteLine("Stack Trace: ");
                        if (ex.StackTrace != null)
                        {
                            sw.WriteLine(ex.StackTrace);
                            sw.WriteLine();
                        }

                        sw.Close();
                    }
                }
                catch(Exception)
                {
                }
                finally
                {
                }
            }

            return false;
        }

        private static void AuthenticateUser(string credentials)
        {
            try
            {
                var encoding = Encoding.GetEncoding("iso-8859-1");
                credentials = encoding.GetString(Convert.FromBase64String(credentials));

                int separator = credentials.IndexOf(':');
                string name = credentials.Substring(0, separator);
                string password = credentials.Substring(separator + 1);

                if (CheckPassword(name, password))
                {
                    var identity = new GenericIdentity(name);
                    SetPrincipal(new GenericPrincipal(identity, null));
                }
                else
                {
                    HttpContext.Current.Response.StatusCode = 401;
                }
            }
            catch (FormatException)
            {
                HttpContext.Current.Response.StatusCode = 401;
            }
        }

        private static void AuthenticateUser(string name, string password)
        {
            try
            {
                if (CheckPassword(name, password))
                {
                    var identity = new GenericIdentity(name);
                    SetPrincipal(new GenericPrincipal(identity, null));
                }
                else
                {
                    HttpContext.Current.Response.StatusCode = 401;
                }
            }
            catch (FormatException)
            {
                HttpContext.Current.Response.StatusCode = 401;
            }
        }

        private static string[] ParseAuthHeader(string authHeader)
        {
            if (authHeader == null || authHeader.Length == 0 || !authHeader.StartsWith("Basic"))
            {
                return null;
            }

            string base64Credentials = authHeader.Substring(6);

            string[] credentials = Encoding.ASCII.GetString(Convert.FromBase64String(base64Credentials)).Split(new char[] { ':' });
            if (credentials.Length != 2 || string.IsNullOrEmpty(credentials[0]) || string.IsNullOrEmpty(credentials[0]))
            {
                return null;
            }

            return credentials;
        }

        private static void OnApplicationBeginRequest(object sender, EventArgs e)
        {
            var request = HttpContext.Current.Request;
            var authHeader = request.Headers["Authorization"];
            if (authHeader == null)
            {
                HttpContext context = HttpContext.Current;

                context.Response.StatusCode = 401;
                context.Response.End();
            }
        }

        private static void OnApplicationAuthenticateRequest(object sender, EventArgs e)
        {
            var request = HttpContext.Current.Request;
            var authHeader = request.Headers["Authorization"];
            if (authHeader != null)
            {
                string[] authHeaderVal = ParseAuthHeader(authHeader);

                AuthenticateUser(authHeaderVal[0], authHeaderVal[1]);

                //var authHeaderVal = AuthenticationHeaderValue.Parse(authHeader);

                //// RFC 2617 sec 1.2, "scheme" name is case-insensitive
                //if (authHeaderVal.Scheme.Equals("basic", StringComparison.OrdinalIgnoreCase) && authHeaderVal.Parameter != null)
                //{
                //    AuthenticateUser(authHeaderVal.Parameter);
                //}
            }
        }

        private static void OnApplicationEndRequest(object sender, EventArgs e)
        {
            var response = HttpContext.Current.Response;
            if (response.StatusCode == 401)
            {
                response.Headers.Add("WWW-Authenticate", string.Format("Basic realm=\"{0}\"", Realm));
            }
        }

        public void Dispose()
        {
        }
    }
}