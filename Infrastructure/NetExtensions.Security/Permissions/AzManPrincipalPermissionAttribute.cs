#region Using

using System;
using System.Security;
using System.Security.Permissions;

#endregion Using

namespace NetExtensions.Security.Permissions
{
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true, Inherited = false)]
    public class AzManPrincipalPermissionAttribute : CodeAccessSecurityAttribute
    {

        #region Properties

        public bool IsAuthenticated { get; set; }
        public string Operation { get; set; }

        #endregion Properties

        #region Constructors

        public AzManPrincipalPermissionAttribute(SecurityAction action)
            : base(action)
        {
            IsAuthenticated = true;
        }

        #endregion Constructors

        #region Methods

        #region Public

        public override IPermission CreatePermission()
        {
            if (base.Unrestricted)
            {
                return new AzManPrincipalPermission(PermissionState.Unrestricted);
            }
            return new AzManPrincipalPermission(IsAuthenticated, new string[] { Operation });
        }

        #endregion Public

        #endregion Methods

    }
}
