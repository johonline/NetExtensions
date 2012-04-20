#region Using

using System;
using System.Collections;
using System.Collections.Specialized;
using System.Configuration.Provider;
using System.Linq;
using System.Runtime.InteropServices;
using System.Web.Security;
using AZROLESLib;

#endregion Using

namespace NetExtensions.Security
{
    public class AzManRoleProvider : RoleProvider
    {

        #region Properties

        public override string ApplicationName { get; set; }
        public string ConnectionString { get; private set; }

        #endregion Properties

        #region Constructors

        public AzManRoleProvider()
        {
        }

        #endregion Constructors

        #region Methods

        #region Provider

        /// <summary>
        /// Initializes the Provider.
        /// </summary>
        public override void Initialize(string name, NameValueCollection config)
        {
            base.Initialize(name, config);

            ApplicationName = config["applicationName"];
            if (string.IsNullOrEmpty(ApplicationName))
            {
                throw new AzManProviderException(Resources.SecurityResources.MessageAzManApplicationNameNotSpecified);
            }

            ConnectionString = Configuration.Settings.AzManConnectionString;
            if (string.IsNullOrEmpty(ConnectionString))
            {
                throw new AzManProviderException(Resources.SecurityResources.MessageAzManConnectionStringNotSpecified);
            }
        }  

        /// <summary>
        /// Adds the specified user names to the specified roles for the configured Application Name.
        /// </summary>
        /// <param name="userNames">A string array of user names to be added to the specified roles.</param>
        /// <param name="roleNames">A string array of the role names to add the specified user names to.</param>
        /// <exception cref="ArgumentNullException">If the specified Role Names or User Names are null.</exception>
        /// <exception cref="ArgumentException">If the specified Role Names or User Names are empty.</exception>
        /// <exception cref="ProviderException">If the specified Role Names or User Names already exist for the configured Application Name.</exception>
        /// <exception cref="AzManProviderException">If another exception occurs.</exception>
        public override void AddUsersToRoles(string[] userNames, string[] roleNames)
        {
            CheckArrayParameter(ref roleNames, true, true, true, 0, "roleNames");
            CheckArrayParameter(ref userNames, true, true, true, 0, "userNames");

            var roles = new object[roleNames.Length];
            int i = 0;
            foreach (var roleName in roleNames)
            {
                var role = GetRole(roleName);
                if (role == null)
                {
                    throw new ProviderException(string.Format(Resources.SecurityResources.MessageAzManRoleDoesNotExist, roleName));
                }
                roles[i++] = role;
            }

            using (var store = new AzManStore(ApplicationName, ConnectionString))
            {
                try
                {
                    foreach (var userName in userNames)
                    {
                        var user = Membership.GetUser(userName);
                        if (user == null)
                        {
                            throw new ProviderException(string.Format(Resources.SecurityResources.MessageAzManUserDoesNotExist, userName));
                        }
                        var sid = user.ProviderUserKey.ToString();

                        try
                        {
                            foreach (IAzRole role in roles)
                            {
                                role.AddMember(sid, null);
                                role.Submit(0, null);
                            }
                        }
                        catch (Exception ex)
                        {
                            throw new AzManProviderException(Resources.SecurityResources.MessageAzManAnExceptionOccured, ex);
                        }
                    }
                }
                finally
                {
                    foreach (var role in roles)
                    {
                        Marshal.FinalReleaseComObject(role);
                    }
                }
            }
        }

        /// <summary>
        /// Adds a new role to the data source for the configured Application Name. 
        /// </summary>
        /// <param name="roleName">A valid Role Name.</param>
        /// <exception cref="ArgumentNullException">If the specified Role Name is null.</exception>
        /// <exception cref="ArgumentException">If the specified Role Name is empty.</exception>
        /// <exception cref="ProviderException">If the specified Role Name already exists for the configured Application Name.</exception>
        /// <exception cref="AzManProviderException">If another exception occurs.</exception>
        public override void CreateRole(string roleName)
        {
            CheckParameter(ref roleName, true, true, true, 0, "roleName");

            using (var store = new AzManStore(ApplicationName, ConnectionString))
            {
                if (RoleExists(roleName))
                {
                    throw new ProviderException(string.Format(Resources.SecurityResources.MessageAzManRoleAlreadyExists, roleName));
                }

                try
                {
                    var task = store.Application.CreateTask(roleName, null);
                    task.IsRoleDefinition = 1;
                    task.Submit(0, null);
                    var role = store.Application.CreateRole(roleName, null);
                    role.AddTask(roleName, null);
                    role.Submit(0, null);
                }
                catch (Exception ex)
                {
                    throw new AzManProviderException(Resources.SecurityResources.MessageAzManAnExceptionOccured, ex);
                }
            }
        }

        /// <summary>
        /// Removes a role from the data source for the configured Application Name.
        /// </summary>
        /// <param name="roleName">The name of the role to delete.</param>
        /// <param name="throwOnPopulatedRole">If true, throw an exception if roleName has one or more members and do not delete roleName.</param>
        /// <returns>true if the role was successfully deleted; otherwise, false.</returns>
        /// <exception cref="ArgumentNullException">If the specified Role Name is null.</exception>
        /// <exception cref="ArgumentException">If the specified Role Name is empty.</exception>
        /// <exception cref="ProviderException">If throwOnPopulatedRole true, and the specified Role Name has one or more members.</exception>
        /// <exception cref="AzManProviderException">If another exception occurs.</exception>
        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            CheckParameter(ref roleName, true, true, true, 0, "roleName");

            if (RoleExists(roleName) == false)
            {
                return false;
            }

            if (throwOnPopulatedRole)
            {
                string[] usersInRole;
                try
                {
                    usersInRole = GetUsersInRole(roleName);
                }
                catch
                {
                    return false;
                }
                if (usersInRole.Length != 0)
                {
                    throw new ProviderException(string.Format(Resources.SecurityResources.MessageAzManRoleIsNotEmpty, roleName));
                }
            }

            using (var store = new AzManStore(ApplicationName, ConnectionString))
            {
                try
                {
                    store.Application.DeleteTask(roleName, null);
                    store.Application.DeleteRole(roleName, null);
                }
                catch (Exception ex)
                {
                    throw new AzManProviderException(Resources.SecurityResources.MessageAzManAnExceptionOccured, ex);
                }
            }

            return true;
        }

        /// <summary>
        /// Not Implemented.
        /// </summary>
        public override string[] FindUsersInRole(string roleName, string userNameToMatch)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Gets a list of all the roles for the configured Application Name.
        /// </summary>
        /// <returns>A string array containing the names of all the roles stored in the data source for the configured Application Name.</returns>
        /// <exception cref="AzManProviderException">If an exception occurs.</exception>
        public override string[] GetAllRoles()
        {
            var list = new string[0];

            using (var store = new AzManStore(ApplicationName, ConnectionString))
            {
                try
                {
                    var roles = store.Application.Roles;
                    list = (from IAzRole role in roles select role.Name).ToArray();
                }
                catch (Exception ex)
                {
                    throw new AzManProviderException(Resources.SecurityResources.MessageAzManAnExceptionOccured, ex);
                }
            }

            return list;
        }

        /// <summary>
        /// Returns a list of the roles that a specified user is in for the configured Application Name. 
        /// Returns a string array with no element, if no role exists for the specified user for the configured Application Name.
        /// </summary>
        /// <param name="userName">A valid User Name</param>
        /// <returns>The list of User Roles.</returns>
        /// <exception cref="ArgumentNullException">If the specified User Name is null.</exception>
        /// <exception cref="ProviderException">If the specified User Name does not exist for the configured Application Name.</exception>
        /// <exception cref="AzManProviderException">If another exception occurs.</exception>
        public override string[] GetRolesForUser(string userName)
        {
            this.CheckParameter(ref userName, true, false, true, 0, "userName");
            if (userName.Length < 1)
            {
                return new string[0];
            }
            return GetRolesForUserCore(userName);
        }

        private string[] GetRolesForUserCore(string userName)
        {
            var list = new string[0];

            using (var store = new AzManStore(ApplicationName, ConnectionString))
            {
                try
                {
                    var context = (IAzClientContext3)GetClientContext(store, userName);
                    if (context != null)
                    {
                        var roles = (object[])context.GetRoles("");
                        list = (from string role in roles select role).ToArray();
                    }
                }
                catch (Exception ex)
                {
                    throw new AzManProviderException(Resources.SecurityResources.MessageAzManAnExceptionOccured, ex);
                }
            }

            return list;
        }

        /// <summary>
        /// Gets a list of users in the specified role for the configured Application Name.
        /// </summary>
        /// <param name="roleName">The name of the role to get the list of users for.</param>
        /// <returns>A string array containing the names of all the users who are members of the specified role for the configured Application Name.</returns>
        /// <exception cref="ArgumentNullException">If the specified Role Name is null.</exception>
        /// <exception cref="ArgumentException">If the specified Role Name is empty.</exception>
        /// <exception cref="ProviderException">If the specified Role Name already exists for the configured Application Name.</exception>
        /// <exception cref="AzManProviderException">If another exception occurs.</exception>
        public override string[] GetUsersInRole(string roleName)
        {
            CheckParameter(ref roleName, true, true, true, 0, "roleName");

            var list = new string[0];

            var role = GetRole(roleName);
            if (role == null)
            {
                throw new ProviderException(string.Format(Resources.SecurityResources.MessageAzManRoleDoesNotExist, roleName));
            }

            try
            {
                object members = null;
                try
                {
                    members = role.MembersName;
                }
                finally
                {
                    Marshal.FinalReleaseComObject(role);
                }

                list = (from string member in (IEnumerable)members select member).ToArray();
            }
            catch (Exception ex)
            {
                throw new AzManProviderException(Resources.SecurityResources.MessageAzManAnExceptionOccured, ex);
            }

            return list;
        }

        /// <summary>
        /// Gets a value indicating whether the specified user is in the specified role for the configured Application Name. 
        /// </summary>
        /// <param name="userName">A valid User Name.</param>
        /// <param name="roleName">A valid Role Name.</param>
        /// <returns>Flag that indicates whether the specified user in the specified role.</returns>
        /// <exception cref="ArgumentNullException">If the specified User Name or Role Name is null.</exception>
        /// <exception cref="ProviderException">If the specified User Name or Role Name does not exist for the configured Application Name.</exception>
        /// <exception cref="AzManProviderException">If another exception occurs.</exception>
        public override bool IsUserInRole(string userName, string roleName)
        {
            CheckParameter(ref userName, true, false, true, 0, "userName");
            if (userName.Length < 1)
            {
                return false;
            }
            CheckParameter(ref roleName, true, true, true, 0, "roleName");
            return IsUserInRoleCore(userName, roleName);
        }

        private bool IsUserInRoleCore(string userName, string roleName)
        {
            if (RoleExists(roleName) == false)
            {
                throw new ProviderException(string.Format(Resources.SecurityResources.MessageAzManRoleDoesNotExist, roleName));
            }

            var roles = GetRolesForUser(userName);
            var role = roles.Where(r => r == roleName).FirstOrDefault();

            return (role != null);
        }

        /// <summary>
        /// Removes the specified user names from the specified roles for the configured Application Name.
        /// </summary>
        /// <param name="userNames">A string array of user names to be removed from the specified roles.</param>
        /// <param name="roleNames">A string array of the role names to remove the specified user names from.</param>
        /// <exception cref="ArgumentNullException">If the specified Role Names or User Names are null.</exception>
        /// <exception cref="ArgumentException">If the specified Role Names or User Names are empty.</exception>
        /// <exception cref="ProviderException">If the specified Role Names or User Names already exist for the configured Application Name.</exception>
        /// <exception cref="AzManProviderException">If another exception occurs.</exception>
        public override void RemoveUsersFromRoles(string[] userNames, string[] roleNames)
        {
            CheckArrayParameter(ref roleNames, true, true, true, 0, "roleNames");
            CheckArrayParameter(ref userNames, true, true, true, 0, "userNames");

            var roles = new object[roleNames.Length];
            int i = 0;
            foreach (var roleName in roleNames)
            {
                var role = GetRole(roleName);
                if (role == null)
                {
                    throw new ProviderException(string.Format(Resources.SecurityResources.MessageAzManRoleDoesNotExist, roleName));
                }
                roles[i++] = role;
            }

            using (var store = new AzManStore(ApplicationName, ConnectionString))
            {
                try
                {
                    foreach (var userName in userNames)
                    {
                        var user = Membership.GetUser(userName);
                        if (user == null)
                        {
                            throw new ProviderException(string.Format(Resources.SecurityResources.MessageAzManUserDoesNotExist, userName));
                        }
                        var sid = user.ProviderUserKey.ToString();

                        try
                        {
                            foreach (IAzRole role in roles)
                            {
                                if (IsUserInRole(userName, role.Name))
                                {
                                    role.DeleteMember(sid, null);
                                    role.Submit(0, null);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            throw new AzManProviderException(Resources.SecurityResources.MessageAzManAnExceptionOccured, ex);
                        }
                    }
                }
                finally
                {
                    foreach (var role in roles)
                    {
                        Marshal.FinalReleaseComObject(role);
                    }
                }
            }
        }

        /// <summary>
        /// Gets a value indicating whether the specified role name already exists in the role data source for the configured Application Name.
        /// </summary>
        /// <param name="roleName">The name of the role to search for in the data source.</param>
        /// <returns>true if the role name already exists in the data source for the configured applicationName; otherwise, false.</returns>
        /// <exception cref="ArgumentNullException">If the specified Role Name is null.</exception>
        /// <exception cref="ArgumentException">If the specified Role Name is empty.</exception>
        /// <exception cref="AzManProviderException">If another exception occurs.</exception>
        public override bool RoleExists(string roleName)
        {
            CheckParameter(ref roleName, true, true, true, 0, "roleName");

            var success = false;

            object role = null;
            try
            {
                role = GetRole(roleName);
                success = (role != null);
            }
            catch (Exception ex)
            {
                throw new AzManProviderException(Resources.SecurityResources.MessageAzManAnExceptionOccured, ex);
            }
            finally
            {
                if (role != null) Marshal.FinalReleaseComObject(role);
            }

            return success;
        }

        /// <summary>
        /// Returns a list of the operations that a specified user is in for the configured Application Name. 
        /// Returns a string array with no element, if no role exists for the specified user for the configured Application Name.
        /// </summary>
        /// <param name="userName">A valid User Name</param>
        /// <returns>The list of User Roles.</returns>
        /// <exception cref="ArgumentNullException">If the specified User Name is null.</exception>
        /// <exception cref="ProviderException">If the specified User Name does not exist for the configured Application Name.</exception>
        /// <exception cref="AzManProviderException">If another exception occurs.</exception>
        public string[] GetOperationsForUser(string userName)
        {
            CheckParameter(ref userName, true, false, true, 0, "userName");
            if (userName.Length < 1)
            {
                return new string[0];
            }
            return GetOperationsForUserCore(userName);
        }

        private string[] GetOperationsForUserCore(string userName)
        {
            var list = new string[0];

            using (var store = new AzManStore(ApplicationName, ConnectionString))
            {
                try
                {
                    var context = (IAzClientContext3)GetClientContext(store, userName);
                    if (context != null)
                    {
                        var operations = context.GetOperations("");
                        list = (from IAzOperation operation in operations select operation.Name).ToArray();
                    }
                }
                catch (Exception ex)
                {
                    throw new AzManProviderException(Resources.SecurityResources.MessageAzManAnExceptionOccured, ex);
                }
            }

            return list;
        }

        /// <summary>
        /// Gets a value indicating whether the specified user can access the specified operation for the configured Application Name. 
        /// </summary>
        /// <param name="userName">A valid User Name.</param>
        /// <param name="operationName">A valid Operation Name.</param>
        /// <returns>Flag that indicates whether the specified user in the specified operation.</returns>
        /// <exception cref="ArgumentNullException">If the specified User Name or Operation Name is null.</exception>
        /// <exception cref="ArgumentException">If the specified User Name or Operation Name is empty.</exception>
        /// <exception cref="ProviderException">If the specified User Name or Operation Name does not exist for the configured Application Name.</exception>
        /// <exception cref="AzManProviderException">If another exception occurs.</exception>
        public bool CanUserAccessOperation(string userName, string operationName)
        {
            CheckParameter(ref userName, true, false, true, 0, "userName");
            if (userName.Length < 1)
            {
                return false;
            }
            CheckParameter(ref operationName, true, true, true, 0, "operationName");
            return this.CanUserAccessOperationCore(userName, operationName);
        }

        private bool CanUserAccessOperationCore(string userName, string operationName)
        {
            CheckParameter(ref operationName, true, true, true, 0x100, "operationName");

            // TODO: Ensure Operation exists

            var operations = GetOperationsForUser(userName);
            var operation = operations.Where(o => o == operationName).FirstOrDefault();
            return (operation != null);
        }

        #endregion Provider

        #region Utility

        private void CheckParameter(ref string param, bool checkForNull, bool checkIfEmpty, bool checkForCommas, int maxSize, string paramName)
        {
            if (param == null)
            {
                if (checkForNull)
                {
                    throw new ArgumentNullException(paramName);
                }
            }
            else
            {
                param = param.Trim();
                if (checkIfEmpty && (param.Length < 1))
                {
                    throw new ArgumentException(string.Format(Resources.SecurityResources.MessageAzManParameterIsEmpty, paramName));
                }
                if ((maxSize > 0) && (param.Length > maxSize))
                {
                    throw new ArgumentException(string.Format(Resources.SecurityResources.MessageAzManParameterTooLong, paramName, maxSize));
                }
                if (checkForCommas && param.Contains(","))
                {
                    throw new ArgumentException(string.Format(Resources.SecurityResources.MessageAzManParameterCannotContainCommas, paramName));
                }

            }
        }

        private void CheckArrayParameter(ref string[] param, bool checkForNull, bool checkIfEmpty, bool checkForCommas, int maxSize, string paramName)
        {
            if (param == null)
            {
                throw new ArgumentNullException(paramName);
            }
            if (param.Length < 1)
            {
                throw new ArgumentException(string.Format(Resources.SecurityResources.MessageAzManParameterArrayCannotBeEmpty, paramName));
            }
            var hashtable = new Hashtable(param.Length);
            for (int i = param.Length - 1; i >= 0; i--)
            {
                CheckParameter(ref param[i], checkForNull, checkIfEmpty, checkForCommas, maxSize, paramName);
                if (hashtable.Contains(param[i]))
                {
                    throw new ArgumentException(string.Format(Resources.SecurityResources.MessageAzManParameterArrayCannotContainDuplicates, paramName));
                }
                hashtable.Add(param[i], param[i]);
            }
        }

        private IAzClientContext GetClientContext(AzManStore store, string userName)
        {
            var user = Membership.GetUser(userName);
            if (user == null)
            {
                throw new ProviderException(string.Format(Resources.SecurityResources.MessageAzManUserDoesNotExist, userName)); 
            }
            return store.Application.InitializeClientContextFromStringSid(user.ProviderUserKey.ToString(), (int)tagAZ_PROP_CONSTANTS.AZ_CLIENT_CONTEXT_SKIP_GROUP, null);
        }

        private IAzRole GetRole(string roleName)
        {
            IAzRole role = null;

            using (var store = new AzManStore(ApplicationName, ConnectionString))
            {
                try
                {
                    role = store.Application.OpenRole(roleName, null);
                }
                catch (COMException ex)
                { 
                    // Role does not exist
                    if (ex.ErrorCode == -2147023728) return null;
                    throw;
                }
            }

            return role;
        }

        #endregion Utility

        #endregion Methods

    }
}
