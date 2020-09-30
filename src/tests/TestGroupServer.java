import java.util.List;
import java.util.ArrayList;
import java.net.Socket;
import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;

public class TestGroupServer {
    public GroupServer test_gs = null;
    public GroupThread thread;
    
    @Before
    public void setup() {
        test_gs = new GroupServer(8080);
        // Create user list
        String initUser = "tests";
        test_gs.userList = new UserList();
        test_gs.userList.addUser(initUser);
        test_gs.userList.addGroup(initUser, "ADMIN");
        test_gs.userList.addOwnership(initUser, "ADMIN");
        // Create group list
        test_gs.groupList = new GroupList(test_gs.userList);
        
        thread = new GroupThread(null, test_gs);
    }
    
    /*
     * Tests the Initialization Process for the Group Server
     * Makes sure the User and Group Lists where made correctly
     */
    @Test
    public void testInit() {
        ArrayList<String> groups = test_gs.userList.getUserGroups("tests");
        assertEquals(groups.size(), 1);
        
        ArrayList<String> members = test_gs.groupList.getGroupUsers("ADMIN");
        String owner = test_gs.groupList.getGroupOwner("ADMIN");
        
        assertEquals(members.size(), 0);
        assertEquals(owner, "tests");
    }
    
    /*
     * Retrieves a token and checks:
     * - the issuer is the test GroupServer
     * - the subject is the requester of the token
     * - there is one group called admin in groups and none in shown groups
     */
    @Test
    public void testCreateToken() {
        UserToken token = thread.createToken("tests", false, false);
        
        assertEquals(token.getIssuer(), test_gs.name);
        assertEquals(token.getSubject(), "tests");
        
        List<String> groups = token.getGroups();
        List<String> shownGroups = token.getShownGroups();
        
        assertEquals(groups.size(), 1);
        assertEquals(groups.get(0), "ADMIN");
        
        assertEquals(shownGroups.size(), 0);
    }
    
    /*
     * Test to see if group is revealed on request
     */
    @Test
    public void testShowGroup() {
        UserToken token = thread.createToken("tests", false, false);
        
        String result1 = thread.showGroup("ADMIN", token);
        assertEquals(result1, "OK");
        
        ArrayList<String> shownGroups = test_gs.userList.getShown("tests");
        
        assertEquals(shownGroups.size(), 1);
        assertEquals(shownGroups.get(0), "ADMIN");
    }
    
    /*
     * Test to see if all groups are shown on request
     */
    @Test
    public void testShowAll() {
        UserToken token = thread.createToken("tests", false, false);
        
        String result1 = thread.showAll(token);
        assertEquals(result1, "OK");
        
        ArrayList<String> shownGroups = test_gs.userList.getShown("tests");
        
        assertEquals(shownGroups.size(), 1);
        assertEquals(shownGroups.get(0), "ADMIN");
    }
    
    /*
     * Create a single user and make sure it shows in the UserList
     */
    @Test
    public void testCreateUser() {
        UserToken token = thread.createToken("tests", false, false);
        String user1 = "user1";
        
        String result1 = thread.showAll(token);
        assertEquals(result1, "OK");
        
        result1 = thread.createUser(user1, token);
        assertEquals(result1, "OK");
        
        boolean result2 = test_gs.userList.checkUser(user1);
        assertTrue(result2);
    }
    
    /*
     * Create a single group and make sure it shows in the GroupList
     */
    @Test
    public void testCreateGroup() {
        UserToken token = thread.createToken("tests", false, false);
        String user1 = "user1";
        String group1 = "group1";
        
        String result = thread.showAll(token);
        assertEquals(result, "OK");
        
        result = thread.createGroup(group1, token);
        assertEquals(result, "OK");
        
        String owner = test_gs.groupList.getGroupOwner(group1);
        ArrayList<String> users = test_gs.groupList.getGroupUsers(group1);
        assertEquals(owner, "tests");
        assertEquals(users.size(), 0);
    }
    
    /*
     * Create a user and a group and add that user to the group.
     * It should update the UserList and GroupList accordingly
     */
    @Test
    public void testAddUserToGroup() {
        UserToken token = thread.createToken("tests", false, false);
        String user1 = "user1";
        String group1 = "group1";
        
        String result = thread.showAll(token);
        assertEquals(result, "OK");
        
        result = thread.createUser(user1, token);
        assertEquals(result, "OK");
        
        result = thread.createGroup(group1, token);
        assertEquals(result, "OK");
        
        result = thread.showAll(token);
        assertEquals(result, "OK");
        
        result = thread.addUserToGroup(user1, group1, token);
        assertEquals(result, "OK");
        
        String owner = test_gs.groupList.getGroupOwner(group1);
        ArrayList<String> users = test_gs.groupList.getGroupUsers(group1);
        assertEquals(owner, "tests");
        assertEquals(users.size(), 1);
        assertEquals(users.get(0), user1);
        
        ArrayList<String> groups = test_gs.userList.getUserGroups(user1);
        assertEquals(groups.size(), 1);
        assertEquals(groups.get(0), group1);
    }
    
    /*
     * Create a user and then delete it
     */
    @Test
    public void testDeleteUser() {
        UserToken token = thread.createToken("tests", false, false);
        String user1 = "user1";
        
        String result = thread.showAll(token);
        assertEquals(result, "OK");
        
        result = thread.createUser(user1, token);
        assertEquals(result, "OK");
        
        boolean result2 = test_gs.userList.checkUser(user1);
        assertTrue(result2);
        
        result = thread.deleteUser(user1, token);
        assertEquals(result, "OK");
        
        result2 = test_gs.userList.checkUser(user1);
        assertFalse(result2);
    }
    
    /*
     * Create a group and then delete that group
     */
    @Test
    public void testDeleteGroup() {
        UserToken token = thread.createToken("tests", false, false);
        String user1 = "user1";
        String group1 = "group1";
        
        String result = thread.showAll(token);
        assertEquals(result, "OK");
        
        result = thread.createGroup(group1, token);
        assertEquals(result, "OK");
        
        String owner = test_gs.groupList.getGroupOwner(group1);
        ArrayList<String> users = test_gs.groupList.getGroupUsers(group1);
        assertEquals(owner, "tests");
        assertEquals(users.size(), 0);
        
        result = thread.showAll(token);
        assertEquals(result, "OK");
        
        result = thread.deleteGroup(group1, token);
        assertEquals(result, "OK");
        
        boolean result2 = test_gs.groupList.checkGroup(group1);
        assertFalse(result2);
    }
    
    /*
     * Test adding a user to a group then removing that user from
     * the group it was just added to
     */
    @Test
    public void testRemoveUser() {
        UserToken token = thread.createToken("tests", false, false);
        String user1 = "user1";
        String group1 = "group1";
        
        String result = thread.showAll(token);
        assertEquals(result, "OK");
        
        result = thread.createUser(user1, token);
        assertEquals(result, "OK");
        
        result = thread.createGroup(group1, token);
        assertEquals(result, "OK");
        
        result = thread.showAll(token);
        assertEquals(result, "OK");
        
        result = thread.addUserToGroup(user1, group1, token);
        assertEquals(result, "OK");
        
        String owner = test_gs.groupList.getGroupOwner(group1);
        ArrayList<String> users = test_gs.groupList.getGroupUsers(group1);
        assertEquals(owner, "tests");
        assertEquals(users.size(), 1);
        assertEquals(users.get(0), user1);
        
        ArrayList<String> groups = test_gs.userList.getUserGroups(user1);
        assertEquals(groups.size(), 1);
        assertEquals(groups.get(0), group1);
        
        result = thread.removeUserFromGroup(user1, group1, token);
        assertEquals(result, "OK");
        
        users = test_gs.groupList.getGroupUsers(group1);
        assertEquals(owner, "tests");
        assertEquals(users.size(), 0);
        
        groups = test_gs.userList.getUserGroups(user1);
        assertEquals(groups.size(), 0);
    }
    
    /*
     * After a group is shown, this tests if it can hide the group
     */
    @Test
    public void testHideGroup() {
        UserToken token = thread.createToken("tests", false, false);
        
        String result1 = thread.showGroup("ADMIN", token);
        assertEquals(result1, "OK");
        
        ArrayList<String> shownGroups = test_gs.userList.getShown("tests");
        
        assertEquals(shownGroups.size(), 1);
        assertEquals(shownGroups.get(0), "ADMIN");
        
        result1 = thread.hideGroup("ADMIN", token);
        assertEquals(result1, "OK");
        
        shownGroups = test_gs.userList.getShown("tests");
        
        assertEquals(shownGroups.size(), 0);
    }
    
    /*
     * This tests hiding all groups associated with the user
     */
    @Test
    public void testHideAll() {
        UserToken token = thread.createToken("tests", false, false);
        
        String result1 = thread.showGroup("ADMIN", token);
        assertEquals(result1, "OK");
        
        ArrayList<String> shownGroups = test_gs.userList.getShown("tests");
        
        assertEquals(shownGroups.size(), 1);
        assertEquals(shownGroups.get(0), "ADMIN");
        
        result1 = thread.hideAll(token);
        assertEquals(result1, "OK");
        
        shownGroups = test_gs.userList.getShown("tests");
        
        assertEquals(shownGroups.size(), 0);
    }
}
