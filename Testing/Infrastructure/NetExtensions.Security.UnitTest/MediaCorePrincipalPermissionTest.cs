#region Using
using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Web.Security;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using MediaCore.UnitTest;
using MediaCore.Security;
using MediaCore.Security.Permissions;
using MediaCore.Security.Principal;
#endregion Using

namespace Amx.Security.UnitTest
{
    /// <summary>
    /// Summary description for MediaCorePrincipalPermissionTest
    /// </summary>
    [TestClass]
    public class MediaCorePrincipalPermissionTest : ITest
    {
        public TestContext TestContext { get; protected set; }

        #region Additional test attributes
        //
        // You can use the following additional attributes as you write your tests:

        /// <summary>
        /// Use ClassInitialize to run code before running the first test in the class 
        /// </summary>
        /// <param name="testContext"></param>
        [ClassInitialize()]
        public static void MyClassInitialize(TestContext testContext) 
        {
            var user = "UnitTest";
            var provider = (AzManRoleProvider)Roles.Provider;
            provider.AddUsersToRoles(new string[] { user }, new string[] { "Sales Manager" });
            var roles = provider.GetRolesForUser(user);
            var operations = provider.GetOperationsForUser(user);
            var identity = new GenericIdentity(user);
            Thread.CurrentPrincipal = new AzManPrincipal(identity, roles, operations);
        }
        
        // Use ClassCleanup to run code after all tests in a class have run
        [ClassCleanup()]
        public static void MyClassCleanup() 
        {
            var provider = (AzManRoleProvider)Roles.Provider;
            provider.RemoveUsersFromRoles(new string[] { "UnitTest" }, new string[] { "Sales Manager" });
        }
        
        /// Use TestInitialize to run code before running each test
        // [TestInitialize()]
        // public void MyTestInitialize() { }
        //
        // Use TestCleanup to run code after each test has run 
        // [TestCleanup()]
        // public void MyTestCleanup(){ }
        //
        #endregion

        [TestMethod]
        public void DemandPositiveTest1()
        {
            var permission = new AzManPrincipalPermission("SearchPrograms");
            permission.Demand();
        }
    }
}
