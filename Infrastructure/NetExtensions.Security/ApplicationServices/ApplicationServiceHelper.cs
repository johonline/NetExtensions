#region Using

using System;
using System.Globalization;
using System.Security.Principal;
using System.Threading;
using System.Web;
using System.Web.Configuration;

#endregion Using

namespace NetExtensions.Security.ApplicationServices
{
    /// <summary>
    /// This class has been extracted from the System.Web.ApplicationServices assembly.
    /// </summary>
    internal static class ApplicationServiceHelper
    {
        //private static bool _authRequiresSSL;
        //private static bool? _authServiceEnabled;
        //private static Dictionary<string, object> _profileAllowedGet;
        //private static Dictionary<string, object> _profileAllowedSet;
        //private static bool? _profileServiceEnabled;
        private static bool? _roleServiceEnabled;

        internal static void EnsureAuthenticated(HttpContext context)
        {
            bool isAuthenticated = false;
            IPrincipal currentUser = GetCurrentUser(context);
            if (currentUser != null)
            {
                IIdentity identity = currentUser.Identity;
                if (identity != null)
                {
                    isAuthenticated = identity.IsAuthenticated;
                }
            }
            if (!isAuthenticated)
            {
                throw new HttpException(Resources.SecurityResources.MessageUserIsNotAuthenticated);
            }
        }

    //    private static void EnsureAuthenticationConfigLoaded()
    //    {
    //        if (!_authServiceEnabled.HasValue)
    //        {
    //            //ScriptingAuthenticationServiceSection configurationSection = ScriptingAuthenticationServiceSection.GetConfigurationSection();
    //            ScriptingAuthenticationServiceSection configurationSection = GetAuthenticationConfigurationSection();
    //            if (configurationSection != null)
    //            {
    //                _authRequiresSSL = configurationSection.RequireSSL;
    //                _authServiceEnabled = new bool?(configurationSection.Enabled);
    //            }
    //            else
    //            {
    //                _authServiceEnabled = false;
    //            }
    //        }
    //    }

    //    internal static void EnsureAuthenticationServiceEnabled(HttpContext context, bool enforceSSL)
    //    {
    //        if (!AuthenticationServiceEnabled)
    //        {
    //            throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "TODO: AtlasWeb.AppService_Disabled", new object[] { "AuthenticationService" }));
    //        }
    //        if ((enforceSSL && _authRequiresSSL) && !context.Request.IsSecureConnection)
    //        {
    //            throw new HttpException(0x193, "TODO: AtlasWeb.AppService_RequiredSSL");
    //        }
    //    }

    //    private static void EnsureProfileConfigLoaded()
    //    {
    //        if (!_profileServiceEnabled.HasValue)
    //        {
    //            //ScriptingProfileServiceSection configurationSection = ScriptingProfileServiceSection.GetConfigurationSection();
    //            ScriptingProfileServiceSection configurationSection = GetProfileConfigurationSection();
    //            Dictionary<string, object> dictionary = null;
    //            Dictionary<string, object> dictionary2 = null;
    //            bool flag = (configurationSection != null) && configurationSection.Enabled;
    //            if (flag)
    //            {
    //                string[] readAccessProperties = configurationSection.ReadAccessProperties;
    //                if ((readAccessProperties != null) && (readAccessProperties.Length > 0))
    //                {
    //                    dictionary = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
    //                    ParseProfilePropertyList(dictionary, readAccessProperties);
    //                }
    //                string[] writeAccessProperties = configurationSection.WriteAccessProperties;
    //                if ((writeAccessProperties != null) && (writeAccessProperties.Length > 0))
    //                {
    //                    dictionary2 = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
    //                    ParseProfilePropertyList(dictionary2, writeAccessProperties);
    //                }
    //            }
    //            _profileAllowedGet = dictionary;
    //            _profileAllowedSet = dictionary2;
    //            _profileServiceEnabled = new bool?(flag);
    //        }
    //    }

    //    internal static void EnsureProfileServiceEnabled()
    //    {
    //        if (!ProfileServiceEnabled)
    //        {
    //            throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "TODO: AtlasWeb.AppService_Disabled", new object[] { "ProfileService" }));
    //        }
    //    }

        internal static void EnsureRoleServiceEnabled()
        {
            if (!RoleServiceEnabled)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.SecurityResources.MessageAppServiceDisabled, new object[] { "RoleService" }));
            }
        }

        internal static IPrincipal GetCurrentUser(HttpContext context)
        {
            if (context == null)
            {
                return Thread.CurrentPrincipal;
            }
            return context.User;
        }

    //    internal static Collection<ProfilePropertyMetadata> GetProfilePropertiesMetadata()
    //    {
    //        EnsureProfileConfigLoaded();
    //        if (ProfileBase.Properties == null)
    //        {
    //            return new Collection<ProfilePropertyMetadata>();
    //        }
    //        Collection<ProfilePropertyMetadata> collection = new Collection<ProfilePropertyMetadata>();
    //        foreach (SettingsProperty property in ProfileBase.Properties)
    //        {
    //            string name = property.Name;
    //            if (_profileAllowedGet.ContainsKey(name) || _profileAllowedSet.ContainsKey(name))
    //            {
    //                string defaultValue = null;
    //                if (property.DefaultValue != null)
    //                {
    //                    if (property.DefaultValue is string)
    //                    {
    //                        defaultValue = (string) property.DefaultValue;
    //                    }
    //                    else
    //                    {
    //                        defaultValue = Convert.ToBase64String((byte[]) property.DefaultValue);
    //                    }
    //                }
    //                ProfilePropertyMetadata item = new ProfilePropertyMetadata();
    //                item.PropertyName = name;
    //                item.DefaultValue = defaultValue;
    //                item.TypeName = property.PropertyType.AssemblyQualifiedName;
    //                item.AllowAnonymousAccess = (bool) property.Attributes["AllowAnonymous"];
    //                item.SerializeAs = (int) property.SerializeAs;
    //                item.IsReadOnly = property.IsReadOnly;
    //                collection.Add(item);
    //            }
    //        }
    //        return collection;
    //    }

        internal static string GetUserName(IPrincipal user)
        {
            if ((user != null) && (user.Identity != null))
            {
                return user.Identity.Name;
            }
            return string.Empty;
        }

    //    private static void ParseProfilePropertyList(Dictionary<string, object> dictionary, string[] properties)
    //    {
    //        foreach (string str in properties)
    //        {
    //            string str2 = (str == null) ? string.Empty : str.Trim();
    //            if (str.Length > 0)
    //            {
    //                dictionary[str2] = true;
    //            }
    //        }
    //    }

    //    // Properties
    //    internal static bool AuthenticationServiceEnabled
    //    {
    //        get
    //        {
    //            EnsureAuthenticationConfigLoaded();
    //            return _authServiceEnabled.Value;
    //        }
    //    }

    //    internal static Dictionary<string, object> ProfileAllowedGet
    //    {
    //        get
    //        {
    //            EnsureProfileConfigLoaded();
    //            return _profileAllowedGet;
    //        }
    //    }

    //    internal static Dictionary<string, object> ProfileAllowedSet
    //    {
    //        get
    //        {
    //            EnsureProfileConfigLoaded();
    //            return _profileAllowedSet;
    //        }
    //    }

    //    internal static bool ProfileServiceEnabled
    //    {
    //        get
    //        {
    //            EnsureProfileConfigLoaded();
    //            return _profileServiceEnabled.Value;
    //        }
    //    }

        internal static bool RoleServiceEnabled
        {
            get
            {
                if (!_roleServiceEnabled.HasValue)
                {
                    //ScriptingRoleServiceSection configurationSection = ScriptingRoleServiceSection.GetConfigurationSection();
                    ScriptingRoleServiceSection configurationSection = GetRoleConfigurationSection();
                    _roleServiceEnabled = new bool?((configurationSection != null) && configurationSection.Enabled);
                }
                return _roleServiceEnabled.Value;
            }
        }

    //    internal static ScriptingAuthenticationServiceSection GetAuthenticationConfigurationSection()
    //    {
    //        return (ScriptingAuthenticationServiceSection)WebConfigurationManager.GetWebApplicationSection("system.web.extensions/scripting/webServices/authenticationService");
    //    }

    //    internal static ScriptingProfileServiceSection GetProfileConfigurationSection()
    //    {
    //        return (ScriptingProfileServiceSection)WebConfigurationManager.GetWebApplicationSection("system.web.extensions/scripting/webServices/profileService");
    //    }

        internal static ScriptingRoleServiceSection GetRoleConfigurationSection()
        {
            return (ScriptingRoleServiceSection)WebConfigurationManager.GetWebApplicationSection("system.web.extensions/scripting/webServices/roleService");
        }
    }
}
