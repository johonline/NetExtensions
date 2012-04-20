#region Using

using System;
using System.Configuration.Provider;
using System.Security.Permissions;
using System.Security.Principal;
using System.ServiceModel;
using System.ServiceModel.Activation;
using System.Web;
using System.Web.Security;
using NetExtensions.Security.Management;

#endregion Using

namespace NetExtensions.Security.ApplicationServices
{
    [ServiceContract(Namespace = DataContractDefinition.Namespace)]
    [ServiceBehavior(Namespace = DataContractDefinition.Namespace, InstanceContextMode = InstanceContextMode.Single, ConcurrencyMode = ConcurrencyMode.Multiple)]
    [AspNetCompatibilityRequirements(RequirementsMode = AspNetCompatibilityRequirementsMode.Required)]
    [AspNetHostingPermission(SecurityAction.LinkDemand, Level = AspNetHostingPermissionLevel.Minimal)]
    [AspNetHostingPermission(SecurityAction.InheritanceDemand, Level = AspNetHostingPermissionLevel.Minimal)]
    public class AuthorizationService
    {

        #region Constructors

        internal AuthorizationService()
        {
        }

        #endregion Constructors

        #region Methods

        #region Operations

        /// <summary>
        /// Returns the list of operations accessible by the current user.
        /// </summary>
        /// <returns>The list of operation accessible by the current user.</returns>
        [OperationContract]
        public string[] GetOperationsForCurrentUser()
        {
            string[] list = null;

            try
            {
                ApplicationServiceHelper.EnsureRoleServiceEnabled();
                AuthorizationService.EnsureProviderEnabled();
                var currentUser = ApplicationServiceHelper.GetCurrentUser(HttpContext.Current);
                var userName = ApplicationServiceHelper.GetUserName(currentUser);
                list = GetRoleProvider(currentUser).GetOperationsForUser(userName);
            }
            catch (Exception ex)
            {
                LogException(ex);
                throw;
            }
            
            return list;
        }

        /// <summary>
        /// Indicates whether the current user has access to an operation.
        /// </summary>
        /// <param name="operation">A valid operation name.</param>
        /// <returns>Flag that indicates whether the current has access to the operation.</returns>
        [OperationContract]
        public bool CanCurrentUserAccessOperation(string operation)
        {
            var success = false;

            if (operation == null) throw new ArgumentNullException("operation");

            try
            {

                ApplicationServiceHelper.EnsureRoleServiceEnabled();
                AuthorizationService.EnsureProviderEnabled();
                var currentUser = ApplicationServiceHelper.GetCurrentUser(HttpContext.Current);
                var userName = ApplicationServiceHelper.GetUserName(currentUser);
                success = GetRoleProvider(currentUser).CanUserAccessOperation(userName, operation);
            }
            catch (Exception ex)
            {
                LogException(ex);
                throw;
            }

            return success;
        }

        #endregion Operations

        #region Private

        private static void EnsureProviderEnabled()
        {
            if (Roles.Enabled == false) throw new ProviderException(Resources.SecurityResources.MessageRolesFeatureNotEnabled);
        }

        private AzManRoleProvider GetRoleProvider(IPrincipal user)
        {
            var provider = (AzManRoleProvider)Roles.Providers[Roles.Provider.Name];
            if (provider == null) throw new ProviderException(Resources.SecurityResources.MessageRoleProviderNotFound);
            return provider;
        }

        private void LogException(Exception ex)
        {
            new WebServiceErrorEvent(Resources.SecurityResources.MessageUnhandledException, this, ex).Raise();
        }

        #endregion Private

        #endregion Methods

    }
}
