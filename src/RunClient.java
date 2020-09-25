import java.util.StringTokenizer;
import java.util.ArrayList;
import java.util.List;
import java.io.BufferedReader;      // Needed to read from the console
import java.io.InputStreamReader;   // Needed to read from the console
import java.lang.UnsupportedOperationException;

public class RunClient {
    private GroupClient g_cli;
    private FileClient f_cli;
    private UserToken token;
    
    public RunClient() {
        g_cli = new GroupClient();
        f_cli = new FileClient();
    }

    private boolean connect(StringTokenizer cmds) {
        String server_type;
        String server;
        int port;

        if(cmds.countTokens() != 3) {
            System.out.println("Usage: CONNECT <GROUP|FILE> <IP> <PORT>");
            return false;
        }

        server_type = cmds.nextToken().toUpperCase();
        server = cmds.nextToken();
        port = Integer.parseInt(cmds.nextToken());

        switch(server_type) {
        case "GROUP":
            g_cli.connect(server, port);
            break;            
        case "FILE":
            f_cli.connect(server, port);
            break;
        default:
            return false;
        }

        return true;
    }

    private boolean getToken(StringTokenizer args) {
        if (args.countTokens() != 1) {
            System.out.println("Usage: GET <USERNAME>");
            return false;
        }

        token = g_cli.getToken(args.nextToken());
        
        if(token == null) {
            System.out.println("Failed to retrieve token");
            return false;
        }

        System.out.println("Successfully retrieved token");
        return true;
    }

    private boolean mapGroupCommand(String cmd, StringTokenizer args) {
        String user;
        String group;
        
        switch(cmd) {
            case "CUSER":
                if (args.countTokens() != 1) {
                    System.out.println("Usage: CUSER <USER>");
                    // return false;
                } else if (!g_cli.isConnected()) {
                    System.out.println("Group Server is not Connected");
                    // return false;
                }
                user = args.nextToken();
                if(g_cli.createUser(user, token))
                    System.out.printf("Created user: %s\n", user);
                break;
            case "DUSER":
                if (args.countTokens() != 1) {
                    System.out.println("Usage: DUSER <USER>");
                    // return false;
                } else if (!g_cli.isConnected()) {
                    System.out.println("Group Server is not Connected");
                    // return false;
                }
                user = args.nextToken();
                if(g_cli.deleteUser(user, token))
                    System.out.printf("Deleted user: %s\n", user);
                break;
            case "CGROUP":
                if (args.countTokens() != 1) {
                    System.out.println("Usage: CGROUP <GROUP>");
                    // return false;
                } else if (!g_cli.isConnected()) {
                    System.out.println("Group Server is not Connected");
                    // return false;
                }
                group = args.nextToken();
                if(g_cli.createGroup(group, token))
                    System.out.printf("Created group: %s\n", group);
                break;
            case "DGROUP":
                if (args.countTokens() != 1) {
                    System.out.println("Usage: DGROUP <GROUP>");
                    // return false;
                } else if (!g_cli.isConnected()) {
                    System.out.println("Group Server is not Connected");
                    // return false;
                }
                group = args.nextToken();
                if(g_cli.deleteGroup(group, token))
                    System.out.printf("Deleted group: %s\n", group);
                break;
            case "LMEMBERS":
                if (args.countTokens() != 1) {
                    System.out.println("Usage: LMEMBERS <GROUP>");
                    // return false;
                } else if (!g_cli.isConnected()) {
                    System.out.println("Group Server is not Connected");
                    // return false;
                }
                group = args.nextToken();
                List<String> members = g_cli.listMembers(group, token);

                if (members != null) {
                    System.out.printf("Here are the members within group %s:\n", group);
                    for(int index=0; index < members.size(); index++) {
                        System.out.printf("\t%s\n", members.get(index));
                    }
                } else {
                    // return false;
                }
                break;
            case "AUSERTOGROUP":
                if (args.countTokens() != 2) {
                    System.out.println("Usage: AUSERTOGROUP <USER> <GROUP>");
                    // return false;
                }
                user = args.nextToken();
                group = args.nextToken();
                if(g_cli.addUserToGroup(user, group, token)) {
                    System.out.printf("Added user %s to group %s\n", user, group);
                } else {
                    // return false;
                }
                break;
            case "RUSERFROMGROUP":
                if (args.countTokens() != 2) {
                    System.out.println("Usage: RUSERFROMGROUP <USER> <GROUP>");
                    // return false;
                }
                user = args.nextToken();
                group = args.nextToken();
                if(g_cli.deleteUserFromGroup(user, group, token)) {
                    System.out.printf("Removed user %s from group %s\n", user, group);
                } else {
                    // return false;
                }
                break;
            default:
                return false;
        }

        return true;
    }

    private boolean mapFileCommand(String cmd, StringTokenizer args) {
        String src_file;
        String dst_file;
        String group;

        switch(cmd) {
            case "UPLOADF":
                if (args.countTokens() != 3) {
                    System.out.println("Usage: DELETEF <SRC-FILE> <DST-FILE> <GROUP>");
                    // return false;
                } else if (!f_cli.isConnected()) {
                    System.out.println("File Server is not Connected");
                    // return false;
                }

                src_file = args.nextToken();
                dst_file = args.nextToken();
                group = args.nextToken();
                if(f_cli.upload(src_file, dst_file, group, token))
                    System.out.printf("Uploaded file %s to %s in group %s\n", src_file, dst_file, group);
                break;
            case "LFILES":
                throw new UnsupportedOperationException("LFILES");
            case "DOWNLOADF":
                if (args.countTokens() != 2) {
                    System.out.println("Usage: DELETEF <SRC-FILE> <DST-FILE>");
                    // return false;
                } else if (!f_cli.isConnected()) {
                    System.out.println("File Server is not Connected");
                    // return false;
                }

                src_file = args.nextToken();
                dst_file = args.nextToken();
                if(f_cli.download(src_file, dst_file, token))
                    System.out.printf("Downloaded file %s into %s\n", src_file, dst_file);
                break;
            case "DELETEF":
                if (args.countTokens() != 1) {
                    System.out.println("Usage: DELETEF <FILENAME>");
                    // return false;
                } else if (!f_cli.isConnected()) {
                    System.out.println("File Server is not Connected");
                    // return false;
                }

                src_file = args.nextToken();
                if(f_cli.delete(src_file, token))
                    System.out.printf("Deleted file %s\n", src_file);
                break;
            default:
                return false;
        }

        return true;
    }

    public boolean mapCommand(StringTokenizer cmds) {
        if (!cmds.hasMoreTokens()) {
            return true;
        }

        String preformat = cmds.nextToken();
        String cmd = preformat.toUpperCase();

        switch(cmd) {
        case "CONNECT":
            connect(cmds);
            break;
        case "EXIT":
            if (g_cli.isConnected())
                g_cli.disconnect();
            if (f_cli.isConnected())
                f_cli.disconnect();
            return false;

        case "GET":
            if (g_cli.isConnected())
                getToken(cmds);
            else
                System.out.println("Not connected to group client");
            break;
        default:
            // Handle as Group Command or File Command
            if (token == null) {
                System.out.println("Please retrieve token first");
                break;
            }
            if(!(mapGroupCommand(cmd, cmds) || mapFileCommand(cmd, cmds))) {
                System.out.printf("Command %s does not exist\n", preformat);
                break;
            }
            break;
        }

        return true;
    }

    public static void main(String args[]) {
        RunClient rcli = new RunClient();
        StringTokenizer cmd;

        System.out.println("Enter a command, or type \"EXIT\" to quit.");
        do {
            cmd = new StringTokenizer(readInput());
        } while (rcli.mapCommand(cmd));
    }

    private static String readInput() {
        try{
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