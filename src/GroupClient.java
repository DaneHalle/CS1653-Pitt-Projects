/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;  // Used to write objects to the server
import java.io.BufferedReader;      // Needed to read from the console
import java.io.InputStreamReader;   // Needed to read from the console

public class GroupClient extends Client implements GroupClientInterface {

    public boolean mapCommand(String args[]) {
        switch(args[0].toUpperCase()) {
        case "CUSER":
            if (args.length != 2) {
                System.out.println("Invalid format");
                return false;
            }
            if(createUser(args[1], token)) {
                System.out.printf("Created user %s\n", args[1]);
                return true;
            } else {
                System.out.printf("Need to get token %s\n", args[1]);
            }
            break;
        case "DUSER":
            if (args.length != 2) {
                System.out.println("Invalid format");
                return false;
            }
            if(deleteUser(args[1], token)) {
                System.out.printf("Deleted user %s\n", args[1]);
                return true;
            } else {
                System.out.printf("Need to get token %s\n", args[1]);
            }
            break;
        case "CGROUP":
            if (args.length != 2) {
                System.out.println("Invalid format");
                return false;
            }
            if(createGroup(args[1], token)) {
                System.out.printf("Created group %s\n", args[1]);
                return true;
            } else {
                System.out.printf("Need to get token %s\n", args[1]);
            }
            break;
        case "DGROUP":
            if (args.length != 2) {
                System.out.println("Invalid format");
                return false;
            }
            if(deleteGroup(args[1], token)) {
                System.out.printf("Deleted group %s\n", args[1]);
                return true;
            } else {
                System.out.printf("Need to get token owner of group %s\n", args[1]);
            }
            break;
        case "LMEMBERS":
            if (args.length != 2) {
                System.out.println("Invalid format");
                return false;
            }
            List<String> members = listMembers(args[1], token);
            if(members!=null) {
                System.out.printf("Here are the members within group %s:\n", args[1]);
                for(int index=0; index < members.size(); index++) {
                    System.out.printf("\t%s\n", members.get(index));
                }
            }else{
                System.out.printf("Need to get token for owner of group %s\n", args[1]);
            }
            break;
        case "AUSERTOGROUP":
            if (args.length != 3) {
                System.out.println("Invalid format");
                return false;
            }
            if(addUserToGroup(args[1], args[2], token)) {
                System.out.printf("Added user %s to group %s\n", args[1], args[2]);
                return true;
            } else {
                System.out.printf("Need to get token for owner of group %s\n", args[2]);
            }
            break;
        case "RUSERFROMGROUP":
            if (args.length != 3) {
                System.out.println("Invalid format");
                return false;
            }
            if(deleteUserFromGroup(args[1], args[2], token)) {
                System.out.printf("Removed user %s from group %s\n", args[1], args[2]);
                return true;
            } else {
                System.out.printf("Need to get token for owner of group %s\n", args[2]);
            }
            break;
        default:
            System.out.println("Command does not exist");
            return false;
        }

        return false;
    }

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
                for(int index = 0; index<response.getObjContents().size(); index++) {
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

    public static void main(String args[]) {
        // Eror checking for arguments
        if(args.length != 2) {
            System.err.println("Not enough arguments.\n");
            System.err.println("Usage: java GroupClient <Server name or IP> <PORT>");
            System.exit(-1);
        }

        final String server = args[0];
        final int port = Integer.parseInt(args[1]);

        GroupClient cli = new GroupClient();

        // Connect to the server
        boolean connected = cli.connect(server, port);

        while(connected) {
            // Read some commands and run them
            String command = readInput();
            String[] parsed = command.split(" ");
            
            if (parsed.length == 0) {
                continue;
            } else if (parsed[0].toUpperCase().compareTo("GET") == 0) {
                if (parsed.length == 1) {
                    System.out.println("Please provide a username");
                } else {
                    cli.getToken(parsed[1]);
                    if (cli.token == null) {
                        System.out.println("Failed to get token");
                    }
                    System.out.printf("Gotten token for user %s\n", parsed[1]);
                }
            } else if (parsed[0].toUpperCase().compareTo("EXIT") == 0) {
                break;
            } else {
                cli.mapCommand(parsed);
            }

            connected = cli.isConnected();
        } 
        
        cli.disconnect();
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
}
