#region Using

using System;
using System.Configuration.Provider;

#endregion Using

namespace NetExtensions.Security
{
    [Serializable]
    public class AzManProviderException : ProviderException
    {
        public AzManProviderException(string message) : base(message) { }
        public AzManProviderException(string message, Exception innerException) : base(message, innerException) { }
    }
}
