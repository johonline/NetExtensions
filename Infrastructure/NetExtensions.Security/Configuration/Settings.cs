#region Using 

using System;
using System.Configuration;

#endregion Using

namespace NetExtensions.Security.Configuration
{
    public static class Settings
    {
        public static string AzManConnectionString { get; private set; }

        static Settings()
        {
            if (ConfigurationManager.ConnectionStrings["AzManConnectionString"] != null)
            {
                Settings.AzManConnectionString = ConfigurationManager.ConnectionStrings["AzManConnectionString"].ConnectionString;
            }
        }
    }
}
