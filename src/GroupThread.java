/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.Thread;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class GroupThread extends Thread {
    private final Socket socket;
    private GroupServer my_gs;

    public GroupThread(Socket _socket, GroupServer _gs) {
        socket = _socket;
        my_gs = _gs;
    }

    public void run() {
        boolean proceed = true;

        try {
            //Announces connection and opens object streams
            System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            Envelope response;

            response = new Envelope("GROUP");
            response.addObject(null);
            output.writeObject(response);

            do {
                Envelope message = (Envelope)input.readObject();
                output.reset();
                System.out.println(socket.getInetAddress()+":"+socket.getPort()+" | Request received: " + message.getMessage());

                if (message.getMessage().equals("GET")) { //Client wants a token
                    if (message.getObjContents().size() != 1) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        System.out.println("\tFAIL-GET | as request has bad contents.");
                    } else {
                        String username = (String)message.getObjContents().get(0); //Get the username
                        if (username == null) {
                            response = new Envelope("FAIL");
                            response.addObject(null);
                            System.out.println("\tFAIL-GET | as given username was null");
                        } else {
                            UserToken yourToken = createToken(username, false); //Create a token
    
                            //Respond to the client. On error, the client will receive a null token
                            response = new Envelope("OK");
                            response.addObject(yourToken);
                            // System.out.println("\tSuccess");
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("REFRESH")) {
                    if (message.getObjContents().size() != 1) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        System.out.println("\tFAIL-GET | as request has bad contents.");
                    } else {
                        UserToken yourToken = (UserToken)message.getObjContents().get(0); // Extract the token
                        String username = yourToken.getSubject();
                        UserToken newToken = createToken(username, true);
                        // Response to the client. On eror, the clien will reveive a null token
                        response = new Envelope("OK");
                        response.addObject(newToken);
                        // System.out.println("\tSuccess");
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("CUSER")) { //Client wants to create a user
                    if (message.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        System.out.println("\tFAIL-CUSER | as request has bad contents.");
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADUSER");
                            System.out.println("\tFAIL-GET | as request has bad user.");
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            System.out.println("\tFAIL-GET | as request has bad token.");
                        } else {
                            String username = (String)message.getObjContents().get(0); //Extract the username
                            UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                            String action = createUser(username, yourToken);
                            if (action.equals("OK")){
                                response = new Envelope("OK"); //Success
                                // System.out.println("\tSuccess");
                            } else {
                                response = new Envelope("FAIL-CUSER");
                                response.addObject(action.substring(1,action.length()-1));
                                System.out.printf("%s", action);
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("DUSER")) { //Client wants to delete a user
                    if (message.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        System.out.println("\tFAIL-DUSER | as request has bad contents.");
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADUSER");
                            System.out.println("\tFAIL-DUSER | as request has bad user.");
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            System.out.println("\tFAIL-DUSER | as request has bad token.");
                        } else {
                            String username = (String)message.getObjContents().get(0); //Extract the username
                            UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                            String action = deleteUser(username, yourToken);
                            if (action.equals("OK")){
                                response = new Envelope("OK"); //Success
                                // System.out.println("\tSuccess");
                            } else {
                                response = new Envelope("FAIL-DUSER");
                                response.addObject(action.substring(1,action.length()-1));
                                System.out.printf("%s", action);
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("CGROUP")) { //Client wants to create a group
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        System.out.println("\tFAIL-CGROUPC | as request has bad contents.");
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            System.out.println("\tFAIL-CGROUPC | as request has bad group.");
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            System.out.println("\tFAIL-CGROUPC | as request has bad token.");
                        } else {
                            String groupName = (String)message.getObjContents().get(0); //Extract desired group name
                            UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                            String action = createGroup(groupName, yourToken);
                            if (action.equals("OK")){
                                response = new Envelope("OK"); //Success
                                // System.out.println("\tSuccess");
                            } else {
                                response = new Envelope("FAIL-CGROUP");
                                response.addObject(action.substring(1,action.length()-1));
                                System.out.printf("%s", action);
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("DGROUP")) { //Client wants to delete a group
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        System.out.println("\tFAIL-DGROUP | as request has bad contents.");
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            System.out.println("\tFAIL-DGROUP | as request has bad group.");
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            System.out.println("\tFAIL-DGROUP | as request has bad token.");
                        } else {
                            String groupName = (String)message.getObjContents().get(0); //Extract desired group name
                            UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                            String action = deleteGroup(groupName, yourToken);
                            if (action.equals("OK")){
                                response = new Envelope("OK"); //Success
                                // System.out.println("\tSuccess");
                            } else {
                                response = new Envelope("FAIL-DGROUP");
                                response.addObject(action.substring(1,action.length()-1));
                                System.out.printf("%s", action);
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("LMEMBERS")) { //Client wants a list of members in a group
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        System.out.println("\tFAIL-LMEMBERS | as request has bad contents.");
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            System.out.println("\tFAIL-LMEMBERS | as request has bad group.");
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            System.out.println("\tFAIL-LMEMBERS | as request has bad token.");
                        } else {
                            String groupname = (String)message.getObjContents().get(0); //Extract desired group name
                            UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                            String requester = yourToken.getSubject();

                            if (my_gs.userList.checkUser(requester)) {
                                if (my_gs.groupList.checkGroup(groupname)) {
                                    if (my_gs.groupList.getGroupOwner(groupname).equals(requester)) {
                                        if (my_gs.userList.getShown(requester).contains(groupname)) {
                                            response = new Envelope("OK"); //Success
                                            List<String> members = my_gs.groupList.getGroupUsers(groupname);
                                            members.add(0, requester);
            
                                            for(int i=0; i<members.size(); i++){
                                                response.addObject(members.get(i));
                                            }
                                            // System.out.println("\tSuccess");
                                        } else {
                                            response = new Envelope("FAIL-LMEMBERS");
                                            String action = "\t"+requester+" has not escalated permissions for group "+groupname+"\n";
                                            response.addObject(action.substring(1,action.length()-1));
                                            System.out.printf("%s", action);
                                        }
                                    } else {
                                        response = new Envelope("FAIL-LMEMBERS");
                                        String action = "\t"+requester+" is not owner of group "+groupname+"\n";
                                        response.addObject(action.substring(1,action.length()-1));
                                        System.out.printf("%s", action);
                                    }
                                } else {
                                    response = new Envelope("FAIL-LMEMBERS");
                                    String action = "\t"+requester+" is not a member of group "+groupname+"\n";
                                    response.addObject(action.substring(1,action.length()-1));
                                    System.out.printf("%s", action);
                                }
                            } else {
                                response = new Envelope("FAIL-LMEMBERS");
                                String action = "\t"+requester+" is not a user on the server \n";
                                response.addObject(action.substring(1,action.length()-1));
                                System.out.printf("%s", action);
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("AUSERTOGROUP")) { //Client wants to add user to a group
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 3) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        System.out.println("\tFAIL-AUSERTOGROUP | as request has bad contents.");
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADUSER");
                            System.out.println("\tFAIL-AUSERTOGROUP | as request has bad user.");
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            System.out.println("\tFAIL-AUSERTOGROUP | as request has bad group.");
                        }
                        if (message.getObjContents().get(2) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            System.out.println("\tFAIL-AUSERTOGROUP | as request has bad token.");
                        } else {
                            String toAddUsername = (String)message.getObjContents().get(0); //Extract desired user to add
                            String groupName = (String)message.getObjContents().get(1); //Extract desired groupname to add user to
                            UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the user's token

                            String action = addUserToGroup(toAddUsername, groupName, yourToken);
                            if (action.equals("OK")){
                                response = new Envelope("OK");
                                // System.out.println("\tSuccess");
                            } else {
                                response = new Envelope("FAIL-AUSERTOGROUP");
                                response.addObject(action.substring(1,action.length()-1));
                                System.out.printf("%s", action);
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("RUSERFROMGROUP")) { //Client wants to remove user from a group
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 3) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        System.out.println("\tFAIL-RUSERFROMGROUP | as request has bad contents.");
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADUSER");
                            System.out.println("\tFAIL-RUSERFROMGROUP | as request has bad user.");
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            System.out.println("\tFAIL-RUSERFROMGROUP | as request has bad group.");
                        }
                        if (message.getObjContents().get(2) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            System.out.println("\tFAIL-RUSERFROMGROUP | as request has bad token.");
                        } else {
                            String toAddUsername = (String)message.getObjContents().get(0); //Extract desired user to add
                            String groupName = (String)message.getObjContents().get(1); //Extract desired groupname to add user to
                            UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the user's token

                            String action = removeUserFromGroup(toAddUsername, groupName, yourToken);
                            if (action.equals("OK")){
                                response = new Envelope("OK");
                                // System.out.println("\tSuccess");
                            } else {
                                response = new Envelope("FAIL-RUSERFROMGROUP");
                                response.addObject(action.substring(1,action.length()-1));
                                System.out.printf("%s", action);
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("SHOW")) { //Client wants to remove user from a group
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        System.out.println("\tFAIL-SHOW | as request has bad contents.");
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            System.out.println("\tFAIL-SHOW | as request has bad group.");
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-TOKEN");
                            System.out.println("\tFAIL-SHOW | as request has bad token.");
                        } else {
                            String groupName = (String)message.getObjContents().get(0);
                            UserToken yourToken = (UserToken)message.getObjContents().get(1);

                            String action = showGroup(groupName,yourToken);
                            if (action.equals("OK")){
                                response = new Envelope("OK");
                                // System.out.println("\tSuccess");
                            } else {
                                response = new Envelope("FAIL-SHOW");
                                response.addObject(action.substring(1,action.length()-1));
                                System.out.printf("%s", action);
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("SHOWALL")) { //Client wants to remove user from a group
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 1) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        System.out.println("\tFAIL-SHOWALL | as request has bad contents.");
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            System.out.println("\tFAIL-SHOWALL | as request has bad token.");
                        } else {
                            UserToken yourToken = (UserToken)message.getObjContents().get(0); //Extract the user's token

                            String action = showAll(yourToken);
                            if (action.equals("OK")){
                                response = new Envelope("OK");
                                // System.out.println("\tSuccess");
                            } else {
                                response = new Envelope("FAIL-SHOWALL");
                                response.addObject(action.substring(1,action.length()-1));
                                System.out.printf("%s", action);
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("HIDE")) { //Client wants to remove user from a group
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        System.out.println("\tFAIL-HIDE | as request has bad contents.");
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            System.out.println("\tFAIL-HIDE | as request has bad group.");
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            System.out.println("\tFAIL-HIDE | as request has bad token.");
                        } else {
                            String groupName = (String)message.getObjContents().get(0); //Extract desired groupname to add user to
                            UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the user's token

                            String action = hideGroup(groupName, yourToken);
                            if (action.equals("OK")){
                                response = new Envelope("OK");
                                // System.out.println("\tSuccess");
                            } else {
                                response = new Envelope("FAIL-HIDE");
                                response.addObject(action.substring(1,action.length()-1));
                                System.out.printf("%s", action);
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("HIDEALL")) { //Client wants to remove user from a group
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 1) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        System.out.println("\tFAIL-HIDEALL | as request has bad contents.");
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            System.out.println("\tFAIL-HIDEALL | as request has bad token.");
                        } else {
                            UserToken yourToken = (UserToken)message.getObjContents().get(0); //Extract the user's token

                            String action = hideAll(yourToken);
                            if (action.equals("OK")){
                                response = new Envelope("OK");
                                // System.out.println("\tSuccess");
                            } else {
                                response = new Envelope("FAIL-HIDEALL");
                                response.addObject(action.substring(1,action.length()-1));
                                System.out.printf("%s", action);
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("DISCONNECT")) { //Client wants to disconnect
                    socket.close(); //Close the socket
                    proceed = false; //End this communication loop
                } else {
                    response = new Envelope("FAIL"); //Server does not understand client request
                    output.writeObject(response);
                }
            } while(proceed);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    //Method to create tokens
    private UserToken createToken(String username, boolean flag) {
        //Check that user exists
        if (my_gs.userList.checkUser(username)) {
            if (flag) {
                //Issue a new token with server's name, user's name, and user's groups
                UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username), my_gs.userList.getShown(username));
                return yourToken;
            } else {
                //Issue a new token with server's name, user's name, and user's groups
                UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
                return yourToken;
            }
        } else {
            return null;
        }
    }

    //Method to create a user
    private String createUser(String username, UserToken yourToken) {
        String requester = yourToken.getSubject();

        if (!yourToken.getShownGroups().contains("ADMIN") && yourToken.getGroups().contains("ADMIN")) {
            return "\t"+requester+" has not escalated permissions for group ADMIN\n";
        }

        String out="FAIL";

        //Check if requester exists
        if (my_gs.userList.checkUser(requester)) {
            //Get the user's groups
            ArrayList<String> temp = my_gs.userList.getShown(requester);
            //requester needs to be an administrator
            if (temp.contains("ADMIN")) {
                //Does user already exist?
                if (my_gs.userList.checkUser(username)) {
                    out="\t"+username+" is already a user within the system\n";
                    return out; //User already exists
                } else {
                    my_gs.userList.addUser(username);
                    return "OK";
                }
            } else {
                out="\t"+requester+" is not an ADMIN within the system\n";
                return out; //requester not an administrator
            }
        } else {
            out="\t"+requester+" is not a user within the system\n";
            return out; //requester does not exist
        }
    }

    //Method to delete a user
    private String deleteUser(String username, UserToken yourToken) {
        String requester = yourToken.getSubject();

        if (!yourToken.getShownGroups().contains("ADMIN") && yourToken.getGroups().contains("ADMIN")) {
            return "\t"+requester+" has not escalated permissions for group ADMIN\n";
        }

        String out="FAIL";

        //Does requester exist?
        if (my_gs.userList.checkUser(requester)) {
            ArrayList<String> temp = my_gs.userList.getShown(requester);
            //requester needs to be an administer
            if (temp.contains("ADMIN")) {
                //Does user exist?
                if (my_gs.userList.checkUser(username)) {
                    //User needs deleted from the groups they belong
                    ArrayList<String> deleteFromGroups = new ArrayList<String>();

                    //This will produce a hard copy of the list of groups this user belongs
                    for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++) {
                        deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
                    }

                    //Delete the user from the groups
                    //If user is the owner, removeMember will automatically delete group!
                    for(int index = 0; index < deleteFromGroups.size(); index++) {
                        my_gs.groupList.removeMember(username, deleteFromGroups.get(index));
                    }

                    //If groups are owned, they must be deleted
                    ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

                    //Make a hard copy of the user's ownership list
                    for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++) {
                        deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
                    }

                    //Delete owned groups
                    for(int index = 0; index < deleteOwnedGroup.size(); index++) {
                        //Use the delete group method. Token must be created for this action
                        deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
                    }

                    //Delete the user from the user list
                    my_gs.userList.deleteUser(username);

                    out="OK";
                    return out;
                } else {
                    out="\t"+username+" is not a user within the system\n";
                    return out; //User does not exist

                }
            } else {
                out="\t"+requester+" is not an ADMIN within the system\n";
                return out; //requester is not an administer
            }
        } else {
            out="\t"+requester+" is not a user within the system\n";
            return out; //requester does not exist
        }
    }

    private String deleteGroup(String groupname, UserToken token) {
        // TODO: Delete the group
        String requester = token.getSubject();        

        if (!token.getShownGroups().contains(groupname)) {
            return "\t"+requester+" has not escalated permissions for group "+groupname+"\n";
        }

        String out="FAIL";

        if (my_gs.userList.checkUser(requester)) {
            if (my_gs.groupList.checkGroup(groupname)) {
                String groupOwner = my_gs.groupList.getGroupOwner(groupname);
                if (requester.equals(groupOwner)) {
                    ArrayList<String> groupUsers = my_gs.groupList.getGroupUsers(groupname);
                    for(int index = 0; index < groupUsers.size(); index++) {
                        my_gs.userList.removeGroup(groupUsers.get(index), groupname);
                        UserToken remove = createToken(groupUsers.get(index), false);
                        remove.removeFromGroup(groupname);
                    }
                    my_gs.groupList.deleteGroup(groupname);
                    my_gs.userList.removeGroup(requester, groupname);
                    my_gs.userList.removeOwnership(requester, groupname);
                    token.removeFromGroup(groupname);
                    return "OK";
                } else {
                    out="\t"+requester+" is not owner of group "+groupname+"\n";
                }
            } else {
                out="\t"+groupname+" is not already a group within the system\n";
            }
        } else {
            out="\t"+requester+" is not a user within the system\n";
        }
        return out;
    }

    private String createGroup(String groupname, UserToken token) {
        String requester = token.getSubject();

        String out="FAIL";

        if (my_gs.userList.checkUser(requester)) {
            if (!my_gs.groupList.checkGroup(groupname)){
                my_gs.userList.addGroup(requester, groupname);
                my_gs.groupList.addGroup(groupname, requester);
                my_gs.userList.addOwnership(requester, groupname);
                token.addToGroup(groupname);
                return "OK";
            } else {
                out="\t"+groupname+" is already a group within the system\n";
            }
        } else {
            out="\t"+requester+" is not a user within the system\n";
        }
        return out;
    }

    private String addUserToGroup(String toAdd, String groupname, UserToken token) {
        String requester = token.getSubject();
        UserToken toAddToken = createToken(toAdd, false);

        if (!token.getShownGroups().contains(groupname)) {
            return "\t"+requester+" has not escalated permissions for group "+groupname+"\n";
        }

        String out="FAIL";

        //Both toAdd and requester are in groups and group exists
        if (my_gs.userList.checkUser(requester)) {
            if (my_gs.userList.checkUser(toAdd)) {
                if (my_gs.groupList.checkGroup(groupname)) {
                    if (!requester.equals(toAdd)) {
                        if (toAddToken!=null) { 
                            ArrayList<String> currentGroupsForNewUser = my_gs.userList.getUserGroups(toAdd);
                            String owner = my_gs.groupList.getGroupOwner(groupname);
                
                            if (!currentGroupsForNewUser.contains(groupname)) {
                                if (requester.equals(owner)) {
                                    my_gs.userList.addGroup(toAdd, groupname);
                                    my_gs.groupList.addMember(toAdd, groupname);
                                    toAddToken.addToGroup(groupname);
                                    return "OK";
                                } else {
                                    out="\t"+requester+" is not owner of group "+groupname+"\n";
                                }
                            } else {
                                out="\t"+toAdd+" is already apart of group "+groupname+"\n";
                            }
                        } else {
                            out="\tToken is null\n";
                        }
                    } else {
                        out="\t"+requester+" and "+toAdd+" are the same. This would create a permenant group\n";
                    }
                } else {
                    out="\t"+groupname+" not a group within the system\n";
                }
            } else {
                out="\t"+toAdd+" is not a user within the system\n";
            }
        } else {
            out="\t"+requester+" is not a user within the system\n";
        }
        return out;
    }

    private String removeUserFromGroup(String toRemove, String groupname, UserToken token) {
        String requester = token.getSubject();
        UserToken toRemoveToken = createToken(toRemove, false);

        if (!token.getShownGroups().contains(groupname) && token.getGroups().contains(groupname)) {
            return"\t"+requester+" has not escalated permissions for group "+groupname+"\n";
        }

        String out="FAIL";

        //Both toRemove and requester are in groups and group exists
        if (my_gs.userList.checkUser(requester)) {
            if (my_gs.userList.checkUser(toRemove)) {
                if (my_gs.groupList.checkGroup(groupname)) { 
                    if (!requester.equals(toRemove)) {
                        if (toRemoveToken!=null) {
                            ArrayList<String> currentGroupsForNewUser = my_gs.userList.getUserGroups(toRemove);
                            String owner = my_gs.groupList.getGroupOwner(groupname);
                
                            if (currentGroupsForNewUser.contains(groupname)) {
                                if (requester.equals(owner)) {
                                    my_gs.userList.removeGroup(toRemove, groupname);
                                    my_gs.groupList.removeMember(toRemove, groupname);
                                    toRemoveToken.removeFromGroup(groupname);
                                    return "OK";
                                } else {
                                    out="\t"+requester+" is not owner of group "+groupname+"\n";
                                }
                            }else {
                                out="\t"+toRemove+" is not apart of group "+groupname+"\n";
                            }
                        } else {
                            out="\tToken is null\n";
                        }
                    } else {
                        out="\t"+requester+" and "+toRemove+" are the same. This would create a permenant group\n";
                    }
                } else {
                    out="\t"+groupname+" not a group within the system\n";
                }
            } else {
                out="\t"+toRemove+" is not a user within the system\n";
            }
        } else {
            out="\t"+requester+" is not a user within the system\n";
        }
        return out;
    }

    private String showGroup(String groupname, UserToken token) {
        String requester = token.getSubject();

        String out="FAIL";

        if (my_gs.userList.checkUser(requester)){
            if (token.getGroups().contains(groupname)) {
                if (!token.getShownGroups().contains(groupname)) {
                    my_gs.userList.addShown(requester, groupname);
                    token.addToShown(groupname);
                    return "OK";
                } else {
                    out="\t"+requester+" already escalated to show group "+groupname+"\n";
                }
            } else {
                out="\t"+requester+" is not a member of group "+groupname+"\n";
            }
        } else {
            out="\t"+requester+" is not a user within the system\n";
        }
        return out;
    }

    private String showAll(UserToken token) {
        String requester = token.getSubject();

        String out="FAIL";

        if (my_gs.userList.checkUser(requester)) {
            List<String> groups = token.getGroups();
            List<String> shownGroups = token.getShownGroups();
            for(int index = 0; index < groups.size(); index++) {
                if (!shownGroups.contains(groups.get(index))) {
                    my_gs.userList.addShown(requester, groups.get(index));
                    token.addToShown(groups.get(index));
                }
            }
            return "OK";
        } else {
            out="\t"+requester+" is not a user within the system\n";
        }
        return out;
    }

    private String hideGroup(String groupname, UserToken token) {
        String requester = token.getSubject();

        String out="FAIL";

        if (my_gs.userList.checkUser(requester)) { 
            if (token.getShownGroups().contains(groupname)) {
                my_gs.userList.removeShown(requester, groupname);
                token.removeFromShown(groupname); 
                return "OK";
            } else {
                out="\t"+requester+" has not escalated to see group "+groupname+"\n";
            }
        } else {
            out="\t"+requester+" is not a user within the system\n";
        }
        return out;
    }

    private String hideAll(UserToken token) {
        String requester = token.getSubject();

        String out="FAIL";

        if (my_gs.userList.checkUser(requester)) {
            List<String> shownGroups = token.getShownGroups();
            for(int index = 0; index < shownGroups.size(); index++) {
                my_gs.userList.removeShown(requester, shownGroups.get(index));
                token.removeFromShown(shownGroups.get(index));
            }
            return "OK";
        } else {
            System.out.printf("\t%s is not a user within the system\n", requester);
        }
        return out;
    }
}
