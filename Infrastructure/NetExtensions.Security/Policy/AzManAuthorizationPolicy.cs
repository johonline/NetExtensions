#region Using

using System;
using System.IdentityModel.Claims;
using System.IdentityModel.Policy;
using System.Security.Principal;
using System.Web;
using System.Web.Security;
using NetExtensions.Security.Principal;

#endregion Using

namespace NetExtensions.Security.Policy
{
    public class AzManAuthorizationPolicy : IAuthorizationPolicy
    {

        #region Members

        private Guid _id = Guid.NewGuid();

        #endregion Members

        #region Properties

        public string Id { get { return _id.ToString(); } }
        public ClaimSet Issuer { get { return ClaimSet.System; } }

        #endregion Properties

        #region Methods

        #region Public

        public bool Evaluate(EvaluationContext evaluationContext, ref object state)
        {
            var success = false;

            var identity = GetClientIdentity(evaluationContext);
            if (identity != null)
            {
                if (Roles.Enabled)
                {
                    var provider = Roles.Provider;
                    var roles = provider.GetRolesForUser(identity.Name);

                    if (provider is AzManRoleProvider)
                    {
                        var azman = (AzManRoleProvider)provider;
                        var operations = azman.GetOperationsForUser(identity.Name);

                        evaluationContext.Properties["Principal"] = new AzManPrincipal(identity, roles, operations);
                    }
                    else
                    {
                        evaluationContext.Properties["Principal"] = new GenericPrincipal(identity, roles);
                    }
                }
                else
                {
                    evaluationContext.Properties["Principal"] = new GenericPrincipal(identity, null);
                }

                success = true;
            }

            return success;
        }

        #endregion Public

        #region Private

        private IIdentity GetClientIdentity(EvaluationContext evaluationContext)
        {
            var identity = HttpContext.Current.User.Identity;
            if (identity == null || string.IsNullOrEmpty(identity.Name)) return null;
            return identity;
        }

        #endregion Private

        #endregion Methods

    }
}
