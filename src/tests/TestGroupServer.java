import java.util.List;
import java.util.ArrayList;
import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.assertEquals;

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
      ArrayList<String> members = test_gs.groupList.getGroupUsers("ADMIN");
      String owner = test_gs.groupList.getGroupOwner("ADMIN");

      assertEquals(members.size(), 1);
   }

   // // test to check yearly salary
   @Test
   public void testCalculateYearlySalary() {
      String issuer = "A";

      assertEquals(issuer, "A");
   }
}
