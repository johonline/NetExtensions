#region Using

using System;
using System.Linq;
using System.Security.Principal;

#endregion Using

namespace NetExtensions.Security.Principal
{
    public class AzManPrincipal : IPrincipal
    {

        #region Members

        private IIdentity _identity = null;
        private string[] _roles = null;
        private string[] _operations = null;

        #endregion Members

        #region Properties

        public IIdentity Identity { get { return _identity; } }

        #endregion Properties

        #region Constructors

        public AzManPrincipal(IIdentity identity) : this(identity, null, null) { }

        public AzManPrincipal(IIdentity identity, string[] roles, string[] operations)
        {
            _identity = identity;
            _roles = roles;
            _operations = operations;
        }

        #endregion Constructors

        #region Methods

        #region Public

        public bool IsInRole(string role)
        {
            var isInRole = false;
            if (_roles != null)
            {
                isInRole = _roles.Contains(role);
            }
            return isInRole;
        }

        public bool HasRequiredOperations(string[] requiredOperations)
        {
            if (requiredOperations == null || requiredOperations.Length == 0) return true;
            if (_operations == null || _operations.Length == 0) return false;

            var hasOperations = true;
            foreach (var operation in requiredOperations)
            {
                if (_operations.Contains(operation) == false)
                {
                    hasOperations = false;
                    break;
                }
            }
            return hasOperations;
        }

        #endregion Public

        #endregion Methods

    }
}
