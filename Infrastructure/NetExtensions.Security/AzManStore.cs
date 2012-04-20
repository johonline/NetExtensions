#region Using

using System;
using System.Runtime.InteropServices;
using AZROLESLib;

#endregion Using

namespace NetExtensions.Security
{
    internal class AzManStore : IDisposable
    {
        public AzAuthorizationStore Store { get; private set; }
        public IAzApplication Application { get; private set; }

        public AzManStore(string applicationName, string connectionString)
        {
            if (string.IsNullOrEmpty(applicationName)) throw new AzManProviderException(Resources.SecurityResources.MessageAzManApplicationNameNotSpecified);

            try
            {
                Store = new AzAuthorizationStore();
                Store.Initialize(0, connectionString, null);
                Application = Store.OpenApplication(applicationName, null);
            }
            catch (COMException ex)
            {
                throw new AzManProviderException(Resources.SecurityResources.MessageAzManHelperInitializeFailed, ex);
            }
            catch (Exception ex)
            {
                throw new AzManProviderException(string.Format(Resources.SecurityResources.MessageAzManInvalidConnectionString, connectionString), ex);
            }
        }

        public void Dispose()
        {
            if (this.Application == null) return;

            Marshal.FinalReleaseComObject(Application);
            Marshal.FinalReleaseComObject(Store);

            Application = null;
            Store = null;
        }
    }
}
