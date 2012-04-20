#region Using

using System;
using System.Configuration;
using System.Configuration.Provider;
using System.Text;
using System.Web.Security;
using Microsoft.VisualStudio.TestTools.UnitTesting;

#endregion Using

namespace NetExtensions.Security.UnitTest
{
    [TestClass]
    public class AzManRoleProviderTest
    {

        #region Members

        private static AzManRoleProvider _provider = null;

        #endregion Members

        #region Initialize & Cleanup

        [ClassInitialize()]
        public static void OnClassInitialize(TestContext testContext) 
        {
            _provider = (AzManRoleProvider)Roles.Provider;
        }
        
        [TestCleanup()]
        public void OnTestCleanup() 
        {
            _provider.DeleteRole("Testers", false);
        }

        #endregion Initialize & Cleanup

        #region Tests

        #region AddUsersToRoles

        [TestMethod, Description("Adds a User to a Role.")]
        public void CanAddUsersToRoles()
        {
            _provider.CreateRole("Testers");
            _provider.AddUsersToRoles(new string[] { "Tester" }, new string[] { "Testers" });
        }

        [TestMethod, Description("Tries adding a User that does not exist to a Role.")]
        [ExpectedException(typeof(ProviderException))]
        public void AddingInvalidUserToRoleThrowsProviderException()
        {
            _provider.CreateRole("Testers");
            _provider.AddUsersToRoles(new string[] { "foo" }, new string[] { "Testers" });
        }

        [TestMethod, Description("Tries adding a User to a Role that does not exist.")]
        [ExpectedException(typeof(ProviderException))]
        public void AddingUserToInvalidRoleThrowsProviderException()
        {
            _provider.AddUsersToRoles(new string[] { "Tester" }, new string[] { "foo" });
        }

        [TestMethod, Description("Tries adding a User with no name to a Role.")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void AddingNullUserToRoleThrowsArgumentNullException()
        {
            _provider.CreateRole("Tester");
            _provider.AddUsersToRoles(new string[] { null }, new string[] { "Tester" });
        }

        [TestMethod, Description("Tries adding a User to a Role with an empty name .")]
        [ExpectedException(typeof(ArgumentException))]
        public void AddingUserToEmptyRoleThrowsArgumentException()
        {
            _provider.AddUsersToRoles(new string[] { "Tester" }, new string[] { string.Empty });
        }

        #endregion AddUsersToRoles

        #region CreateRole

        [TestMethod, Description("Creates a Role.")]
        public void CanCreateRole()
        {
            _provider.CreateRole("Testers");
        }

        [TestMethod, Description("Tries creating a Role that already exists.")]
        [ExpectedException(typeof(ProviderException))]
        public void CreatingRoleThatAlreadyExistsThrowsProviderException()
        {
            _provider.CreateRole("Testers");
            _provider.CreateRole("Testers");
        }

        [TestMethod, Description("Tries creating a Role with no name.")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CreatingNullRoleThrowsArgumentNullException()
        {
            _provider.CreateRole(null);
        }

        [TestMethod, Description("Tries creating a Role with an empty name .")]
        [ExpectedException(typeof(ArgumentException))]
        public void CreatingEmptyRoleThrowsArgumentException()
        {
            _provider.CreateRole(string.Empty);
        }

        #endregion CreateRole

        #region DeleteRole

        [TestMethod, Description("Deletes a Role with throwOnPopulatedRole true, and no User attached.")]
        public void CanDeleteRoleWithOnPopulatedRoleEqualsToTrue()
        {
            _provider.CreateRole("Testers");
            _provider.DeleteRole("Testers", true);
        }

        [TestMethod, Description("Deletes a Role with throwOnPopulatedRole false, and no User attached.")]
        public void CanDeleteRoleWithOnPopulatedRoleEqualsToFalse()
        {
            _provider.CreateRole("Testers");
            _provider.DeleteRole("Testers", false);
        }

        [TestMethod, Description("Deletes a Role with throwOnPopulatedRole false, and 1 User attached.")]
        public void CanDeleteRoleWithOnPopulatedRoleEqualsToFalseAndExistingUsers()
        {
            _provider.CreateRole("Testers");
            _provider.AddUsersToRoles(new string[] { "Tester" }, new string[] { "Testers" });
            _provider.DeleteRole("Testers", false);
        }

        [TestMethod, Description("Deletes a Role with throwOnPopulatedRole true, and 1 User attached.")]
        [ExpectedException(typeof(ProviderException))]
        public void DeletingRoleWithOnPopulatedRoleEqualsTrueAndExistingUsersThrowsProviderException()
        {
            _provider.CreateRole("Testers");
            _provider.AddUsersToRoles(new string[] { "Tester" }, new string[] { "Testers" });
            _provider.DeleteRole("Testers", true);
        }

        [TestMethod, Description("Tries deleting a Role with no name.")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DeletingNullRoleThrowsArgumentNullException()
        {
            _provider.DeleteRole(null, true);
        }

        [TestMethod, Description("Tries deleting a Role with an empty name .")]
        [ExpectedException(typeof(ArgumentException))]
        public void DeletingEmptyRoleThrowsArgumentException()
        {
            _provider.DeleteRole(string.Empty, false);
        }

        [TestMethod, Description("Tries deleting a Role that does not exist with throwOnPopulatedRole false.")]
        public void CanDeleteInvalidRoleWithOnPopulatedRoleEqualsToFalse()
        {
            _provider.DeleteRole("foo", false);
        }

        [TestMethod, Description("Tries deleting a Role that does not exist with throwOnPopulatedRole true.")]
        public void CanDeleteInvalidRoleWithOnPopulatedRoleEqualsToTrue()
        {
            _provider.DeleteRole("foo", true);
        }

        #endregion DeleteRole

        #region FindUsersInRole

        [TestMethod, Description("FindUsersInRole not Implemented.")]
        [ExpectedException(typeof(NotImplementedException))]
        public void FindingUsersInRoleThrowsNotImplementedException()
        {
            _provider.FindUsersInRole(null, null);
        }

        #endregion FindUsersInRole

        #region GetAllRoles

        [TestMethod, Description("Retrieves all Roles.")]
        public void CanGetAllRoles()
        {
            var list = _provider.GetAllRoles();

            Assert.IsNotNull(list);
            Assert.AreNotEqual(0, list.Length);
        }

        #endregion GetAllRoles

        #region GetRolesForUser

        [TestMethod, Description("Retrieves the list of Roles of a User.")]
        public void CanGetRolesForUser()
        {
            _provider.CreateRole("Testers");
            _provider.AddUsersToRoles(new string[] { "Tester" }, new string[] { "Testers" });
            var list = _provider.GetRolesForUser("Tester");

            Assert.IsNotNull(list);
            Assert.AreEqual(1, list.Length);
        }

        [TestMethod, Description("Retrieves the list of Roles of a User with an empty list.")]
        public void CanGetRolesForUserWithNoRoles()
        {
            var list = _provider.GetRolesForUser("Tester");

            Assert.IsNotNull(list);
            Assert.AreEqual(0, list.Length);
        }

        [TestMethod, Description("Retrieves the list of Roles of a User with an empty name.")]
        public void CanGetRolesForEmptyUser()
        {
            var list = _provider.GetRolesForUser(string.Empty);

            Assert.IsNotNull(list);
            Assert.AreEqual(0, list.Length);
        }

        [TestMethod, Description("Tries retrieving the list of Roles of a User that does not exist.")]
        [ExpectedException(typeof(ProviderException))]
        public void GettingRolesForInvalidUserThrowsProviderException()
        {
            var list = _provider.GetRolesForUser("foo");
        }

        [TestMethod, Description("Tries retrieving the list of Roles of a User with no name.")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void GettingRolesForNullUserThrowsArgumentNullException()
        {
            var list = _provider.GetRolesForUser(null);
        }

        #endregion GetRolesForUser

        #region GetUsersInRole

        [TestMethod, Description("Retrieves the list of Users of a Role.")]
        public void CanGetUsersInRole()
        {
            _provider.CreateRole("Testers");
            _provider.AddUsersToRoles(new string[] { "Tester" }, new string[] { "Testers" });
            var list = _provider.GetUsersInRole("Testers");

            Assert.IsNotNull(list);
            Assert.AreEqual(1, list.Length);
        }

        [TestMethod, Description("Retrieves the list of Users of a Role with an empty list.")]
        public void CanGetUsersInRoleWithNoUsers()
        {
            _provider.CreateRole("Testers");
            var list = _provider.GetUsersInRole("Testers");

            Assert.IsNotNull(list);
            Assert.AreEqual(0, list.Length);
        }

        [TestMethod, Description("Tries retrieving the list of Users of a Role that does not exist.")]
        [ExpectedException(typeof(ProviderException))]
        public void GettingUsersInInvalidRoleThrowsProviderException()
        {
            var list = _provider.GetUsersInRole("foo");
        }

        [TestMethod, Description("Tries retrieving the list of Users of a Role with no name.")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void GettingUsersInNullRoleThrowsArgumentNullException()
        {
            var list = _provider.GetUsersInRole(null);
        }

        [TestMethod, Description("Tries retrieving the list of Users of a Role with an empty name.")]
        [ExpectedException(typeof(ArgumentException))]
        public void GettingUsersInEmptyRoleThrowsArgumentException()
        {
            var list = _provider.GetUsersInRole(string.Empty);
        }

        #endregion GetUsersInRole

        #region IsUserInRole

        [TestMethod, Description("Checks whether a User is in a Role (true).")]
        public void CanCheckIfUserInRole()
        {
            _provider.CreateRole("Testers");
            _provider.AddUsersToRoles(new string[] { "Tester" }, new string[] { "Testers" });
            var result = _provider.IsUserInRole("Tester", "Testers");

            Assert.IsTrue(result);
        }

        [TestMethod, Description("Checks whether a User is in a Role (false).")]
        public void CanCheckIfUserNotInRole()
        {
            _provider.CreateRole("Testers");
            var result = _provider.IsUserInRole("Tester", "Testers");

            Assert.IsFalse(result);
        }

        [TestMethod, Description("Tries checking whether a User is in a Role that does not exist.")]
        [ExpectedException(typeof(ProviderException))]
        public void CheckingIfUserInInvalidRoleThrowsProviderException()
        {
            var result = _provider.IsUserInRole("Tester", "foo");
        }

        [TestMethod, Description("Tries checking whether a User that does not exist is in a Role.")]
        [ExpectedException(typeof(ProviderException))]
        public void CheckingIfInvalidUserInRoleThrowsProviderException()
        {
            _provider.CreateRole("Testers");
            var result = _provider.IsUserInRole("foo", "Testers");
        }

        [TestMethod, Description("Tries checking whether a User with no name is in a Role.")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CheckingIfNullUserInRoleThrowsArgumentNullException()
        {
            _provider.CreateRole("Testers");
            var list = _provider.IsUserInRole(null, "Testers");
        }

        [TestMethod, Description("Tries checking whether a User is in a Role with an empty name.")]
        [ExpectedException(typeof(ArgumentException))]
        public void CheckingIfUserInEmptyRoleThrowsArgumentException()
        {
            var list = _provider.IsUserInRole("Tester", string.Empty);
        }

        #endregion IsUserInRole

        #region RemoveUsersFromRoles

        [TestMethod, Description("Removes a User from a Role.")]
        public void CanRemoveUsersFromRoles()
        {
            _provider.CreateRole("Testers");
            _provider.AddUsersToRoles(new string[] { "Tester" }, new string[] { "Testers" });
            _provider.RemoveUsersFromRoles(new string[] { "Tester" }, new string[] { "Testers" });
        }

        [TestMethod, Description("Tries removing a User that does not exist from a Role.")]
        [ExpectedException(typeof(ProviderException))]
        public void RemovingInvalidUserFromRolesThrowsProviderException()
        {
            _provider.CreateRole("Testers");
            _provider.RemoveUsersFromRoles(new string[] { "foo" }, new string[] { "Testers" });
        }

        [TestMethod, Description("Tries removing a User from a Role that does not exist.")]
        [ExpectedException(typeof(ProviderException))]
        public void RemovingUserFromIvalidRoleThrowsProviderException()
        {
            _provider.RemoveUsersFromRoles(new string[] { "Tester" }, new string[] { "foo" });
        }

        [TestMethod, Description("Tries removing a User with no name from a Role.")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void RemovingNullUserFromRoleThrowsArgumentNullException()
        {
            _provider.CreateRole("Testers");
            _provider.RemoveUsersFromRoles(new string[] { null }, new string[] { "Testers" });
        }

        [TestMethod, Description("Tries adding a User to a Role with an empty name .")]
        [ExpectedException(typeof(ArgumentException))]
        public void RemovingUserFromEmptyRoleThrowsArgumentException()
        {
            _provider.RemoveUsersFromRoles(new string[] { "UnitTest" }, new string[] { string.Empty });
        }

        #endregion RemoveUsersFromRoles

        #region RoleExists

        [TestMethod, Description("Checks whether a Role exists (true).")]
        public void CanCheckIfRoleExists()
        {
            _provider.CreateRole("Testers");
            var result = _provider.RoleExists("Testers");

            Assert.IsTrue(result);
        }

        [TestMethod, Description("Checks whether a Role exists (false).")]
        public void CanCheckIfRoleDoesNotExist()
        {
            var result = _provider.RoleExists("Testers");

            Assert.IsFalse(result);
        }

        [TestMethod, Description("Tries checking whether a Role with no name exists.")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CheckingIfNullRoleExistsThrowsArgumentNullException()
        {
            _provider.RoleExists(null);
        }

        [TestMethod, Description("Tries checking whether a Role with an empty name .")]
        [ExpectedException(typeof(ArgumentException))]
        public void CheckingIfEmptyRoleExistsThrowsArgumentException()
        {
            _provider.RoleExists(string.Empty);
        }

        #endregion RoleExists

        #region GetOperationsForUser

        [TestMethod, Description("Retrieves the list of Roles of a User.")]
        public void CanGetOperationsForUser()
        {
            _provider.CreateRole("Testers");
            _provider.AddUsersToRoles(new string[] { "Tester" }, new string[] { "Testers" });
            var list = _provider.GetOperationsForUser("Tester");

            Assert.IsNotNull(list);
            Assert.AreNotEqual(0, list.Length);
        }

        [TestMethod, Description("Retrieves the list of Roles of a User with an empty list.")]
        public void CanGetOperationsForUserWithNoRole()
        {
            var list = _provider.GetOperationsForUser("Tester");

            Assert.IsNotNull(list);
            Assert.AreEqual(0, list.Length);
        }

        [TestMethod, Description("Retrieves the list of Roles of a User with an empty name.")]
        public void CanGetOperationsForEmptyUser()
        {
            var list = _provider.GetOperationsForUser(string.Empty);

            Assert.IsNotNull(list);
            Assert.AreEqual(0, list.Length);
        }

        [TestMethod, Description("Tries retrieving the list of Roles of a User that does not exist.")]
        [ExpectedException(typeof(ProviderException))]
        public void GettingOperationsForInvalidUserThrowsProviderException()
        {
            var list = _provider.GetOperationsForUser("foo");
        }

        [TestMethod, Description("Tries retrieving the list of Roles of a User with no name.")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void GettingOperationsForNullUserThrowsArgumentNullException()
        {
            var list = _provider.GetOperationsForUser(null);
        }

        #endregion GetOperationsForUser

        #region CanUserAccessOperation

        [TestMethod, Description("Checks whether a User can access an Operation (true).")]
        public void CanCheckIfUserAccessOperation()
        {
            _provider.AddUsersToRoles(new string[] { "Tester" }, new string[] { "Testers" });
            var result = _provider.CanUserAccessOperation("Tester", "Operation Test");

            Assert.IsTrue(result);
        }

        [TestMethod, Description("Checks whether a User can access an Operation (false).")]
        public void CanCheckIfUserWithNoRoleAccessOperation()
        {
            var result = _provider.CanUserAccessOperation("Tester", "Operation Test");

            Assert.IsFalse(result);
        }

        [TestMethod, Description("Checks whether a User with an empty name can access an Operation.")]
        public void CanCheckIfEmptyUserAccessOperation()
        {
            var result = _provider.CanUserAccessOperation(string.Empty, "Operation Test");

            Assert.IsFalse(result);
        }

        [TestMethod, Description("Tries checking whether a User that does not exist can access an Operation.")]
        [ExpectedException(typeof(ProviderException))]
        public void CheckingIfInvalidUserAccessOperationThrowsProviderException()
        {
            var list = _provider.CanUserAccessOperation("foo", "Operation Test");
        }

        [TestMethod, Description("Tries checking whether a User with no name can access an Operation.")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CheckingIfNullUserAccessOperationThrowsArgumentNullException()
        {
            var list = _provider.CanUserAccessOperation(null, "Operation Test");
        }

        [TestMethod, Description("Tries checking whether a User can access an Operation with an empty name.")]
        [ExpectedException(typeof(ArgumentException))]
        public void CheckingIfUserAccessEmptyOperationThrowsArgumentException()
        {
            var list = _provider.CanUserAccessOperation("Tester", string.Empty);
        }

        #endregion CanUserAccessOperation

        #endregion Tests

    }
}
