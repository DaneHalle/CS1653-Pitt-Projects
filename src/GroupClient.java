/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;  // Used to write objects to the server
import java.io.BufferedReader;      // Needed to read from the console
import java.io.InputStreamReader;   // Needed to read from the console

public class GroupClient extends Client implements GroupClientInterface {

    public UserToken getToken(String username) {
        try {
            UserToken token = null;
            Envelope message = null, response = null;

            //Tell the server to return a token.
            message = new Envelope("GET");
            message.addObject(username); //Add user name string
            output.writeObject(message);

            //Get the response from the server
            response = (Envelope)input.readObject();

            //Successful response
            if(response.getMessage().equals("OK")) {
                //If there is a token in the Envelope, return it
                ArrayList<Object> temp = null;
                temp = response.getObjContents();

                if(temp.size() == 1) {
                    token = (UserToken)temp.get(0);
                    return token;
                }
            }

            return null;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }

    }

    public UserToken refreshToken(UserToken token) {
        try {
            UserToken newToken = null;
            Envelope message = null, response = null;

            //Tell the server to return a token.
            message = new Envelope("REFRESH");
            message.addObject(token); //Add user name string
            output.writeObject(message);

            //Get the response from the server
            response = (Envelope)input.readObject();

            //Successful response
            if(response.getMessage().equals("OK")) {
                //If there is a token in the Envelope, return it
                ArrayList<Object> temp = null;
                temp = response.getObjContents();

                if(temp.size() == 1) {
                    newToken = (UserToken)temp.get(0);
                    // List<String> groups = newToken.getShownGroups();
                    // for(int index = 0; index < groups.size(); index++) {
                    //     System.out.println(groups.get(index));
                    // }

                    return newToken;
                }
            }

            return null;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }

    }

    public boolean createUser(String username, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a user
            message = new Envelope("CUSER");
            message.addObject(username); //Add user name string
            message.addObject(token); //Add the requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }
            
            System.out.printf("FAILED: %s\n", response.getMessage());
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteUser(String username, UserToken token) {
        try {
            Envelope message = null, response = null;

            //Tell the server to delete a user
            message = new Envelope("DUSER");
            message.addObject(username); //Add user name
            message.addObject(token);  //Add requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }

            System.out.printf("FAILED: %s\n", response.getMessage());
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean createGroup(String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a group
            message = new Envelope("CGROUP");
            message.addObject(groupname); //Add the group name string
            message.addObject(token); //Add the requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }

            System.out.printf("FAILED: %s\n", response.getMessage());
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteGroup(String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to delete a group
            message = new Envelope("DGROUP");
            message.addObject(groupname); //Add group name string
            message.addObject(token); //Add requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();
            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }

            System.out.printf("FAILED: %s\n", response.getMessage());
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    public List<String> listMembers(String group, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to return the member list
            message = new Envelope("LMEMBERS");
            message.addObject(group); //Add group name string
            message.addObject(token); //Add requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();

            //If server indicates success, return the member list
            if(response.getMessage().equals("OK")) {
                List<String> toReturn = new ArrayList<String>();
                for(int index = 0; index < response.getObjContents().size(); index++) {
                    String toAdd = (String)response.getObjContents().get(index);
                    if(!toReturn.contains(toAdd)) {
                        toReturn.add(toAdd);
                    }
                }
                return toReturn;
                // return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
            }

            System.out.printf("FAILED: %s\n", response.getMessage());
            return null;

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }

    public boolean addUserToGroup(String username, String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to add a user to the group
            message = new Envelope("AUSERTOGROUP");
            message.addObject(username); //Add user name string
            message.addObject(groupname); //Add group name string
            message.addObject(token); //Add requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();
            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }

            System.out.printf("FAILED: %s\n", response.getMessage());
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteUserFromGroup(String username, String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to remove a user from the group
            message = new Envelope("RUSERFROMGROUP");
            message.addObject(username); //Add user name string
            message.addObject(groupname); //Add group name string
            message.addObject(token); //Add requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();
            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }

            System.out.printf("FAILED: %s\n", response.getMessage());
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    private static String readInput() {
        try{
            System.out.println("Enter a command, or type \"EXIT\" to quit.");
            System.out.print(" > ");	
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            return in.readLine();
        } catch(Exception e){
            // Uh oh...
            System.err.println("Buffer Reader Error");
            e.printStackTrace();
            return "";
        }
    }

    public boolean showGroup(String group, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a user
            message = new Envelope("SHOW");
            message.addObject(group); //Add group name string
            message.addObject(token); //Add the requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }
            
            System.out.printf("FAILED: %s\n", response.getMessage());
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean showAll(UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a user
            message = new Envelope("SHOWALL");
            message.addObject(token); //Add the requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }
            
            System.out.printf("FAILED: %s\n", response.getMessage());
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }    

    public boolean hideGroup(String group, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a user
            message = new Envelope("HIDE");
            message.addObject(group); //Add group name string
            message.addObject(token); //Add the requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }
            
            System.out.printf("FAILED: %s\n", response.getMessage());
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }

    }

    public boolean hideAll(UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a user
            message = new Envelope("HIDEALL");
            message.addObject(token); //Add the requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }
            
            System.out.printf("FAILED: %s\n", response.getMessage());
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }

    }    
}
