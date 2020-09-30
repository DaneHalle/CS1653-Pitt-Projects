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

   @Test
   public void testInit() {
      ArrayList<String> groups = test_gs.userList.getUserGroups("tests");
      assertEquals(groups.size(), 1);

      ArrayList<String> members = test_gs.groupList.getGroupUsers("ADMIN");
      String owner = test_gs.groupList.getGroupOwner("ADMIN");
   
      assertEquals(members.size(), 0);
      assertEquals(owner, "tests");
   }

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


}
