import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.List;
import java.util.ArrayList;
import java.net.Socket;
import org.junit.Test;
import org.junit.Before;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class TestGroupServer {
   public GroupServer test_gs = null;
   public GroupThread thread;
   public Socket socket;
   public ObjectInputStream input;
   public ObjectOutputStream output;

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

      socket = new Socket();
      input = mock(ObjectInputStream.class);
      output = mock(ObjectOutputStream.class);

      thread = new GroupThread(socket, test_gs);
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

      try {
         when(socket.getInputStream()).thenReturn(input);
         when(socket.getOutputStream()).thenReturn(output);

         when(input.readObject()).thenReturn(new Envelope("GET"));

         thread.run();
         // verify(output).write(valueCapture.capture());
      } catch(Exception e) {

      }

      // Mockito.when(socket.getOutputStream()).thenReturn(myOutputStream);

      // Mockito.verify(myOutputStream).write(valueCapture.capture());
      // byte[] writtenData = valueCapture.getValue();

   }


}
