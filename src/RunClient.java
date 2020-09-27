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

    private enum CommandResult {
        NOTCMD,
        ARGS,
        SUCCESS
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
            g_cli.verify("GROUP");
            break;            
        case "FILE":
            f_cli.connect(server, port);
            f_cli.verify("FILE");
            break;
        default:
            return false;
        }

        return true;
    }

    public void connectionStatus() {
        String g_connection = g_cli.isConnected() ? "CONNECTED" : "DISCONNECTED";
        String f_connection = f_cli.isConnected() ? "CONNECTED" : "DISCONNECTED";
        System.out.println("GROUP SERVER: " + g_connection);
        System.out.println("FILE SERVER: " + f_connection);
    }

    // public void printToken() {
    //     System.out.println("Issuer: " + token.getIssuer());
    //     System.out.println("Subject: " + token.getSubject());
    //     List<String> groups = token.getGroups();
    //     System.out.println("Groups: ");
    //     for(int i=0; i < groups.size(); i++) {
    //         System.out.println(" - " + groups.get(i));
    //     }
    // }

    private boolean getToken(StringTokenizer args) {
        if (args.countTokens() != 1) {
            System.out.println("Usage: GET <USERNAME>");
            return false;
        } else if (!g_cli.isConnected()) {
            System.out.println("Group server is not connected");
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

    private boolean checkCmd(
        StringTokenizer args,
        int args_num,
        String usage,
        boolean is_group
    ) {
        if (args.countTokens() != args_num) {
            System.out.println(usage);
            return false;
        } else if (is_group && !g_cli.isConnected()) {
            System.out.println("ERROR: Group server is not connected");
            return false;
        } else if (!is_group && !f_cli.isConnected()) {
            System.out.println("ERROR: File server is not connected");
            return false;
        }

        // Successful Command, then refresh token with current token
        token = g_cli.refreshToken(token);
        return true;
    }

    private CommandResult mapServerCommand(String cmd, StringTokenizer args) {
        // For the group server
        String user;
        
        // For the file server
        String src_file;
        String dst_file;
        String group;
        
        switch(cmd) {
        case "CUSER":
            if (!checkCmd(args, 1, "Usage: CUSER <USER>", true))
                return CommandResult.ARGS;
            user = args.nextToken();
            if(g_cli.createUser(user, token))
                System.out.printf("Created user: %s\n", user);
            break;
        case "DUSER":
            if (!checkCmd(args, 1, "Usage: DUSER <USER>", true))
                return CommandResult.ARGS;
            user = args.nextToken();
            if(g_cli.deleteUser(user, token))
                System.out.printf("Deleted user: %s\n", user);
            break;
        case "CGROUP":
            if (!checkCmd(args, 1, "Usage: CGROUP <GROUP>", true))
                return CommandResult.ARGS;
            group = args.nextToken();
            if(g_cli.createGroup(group, token))
                System.out.printf("Created group: %s\n", group);
            break;
        case "DGROUP":
            if (!checkCmd(args, 1, "Usage: DGROUP <GROUP>", true))
                return CommandResult.ARGS;
            group = args.nextToken();
            if(g_cli.deleteGroup(group, token))
                System.out.printf("Deleted group: %s\n", group);
            break;
        case "LMEMBERS":
            if (!checkCmd(args, 1, "Usage: LMEMBERS <GROUP>", true))
                return CommandResult.ARGS;
            group = args.nextToken();
            List<String> members = g_cli.listMembers(group, token);

            if (members != null) {
                System.out.printf("Here are the members within group %s:\n", group);
                for(int index=0; index < members.size(); index++) {
                    System.out.printf("\t%s\n", members.get(index));
                }
            }
            break;
        case "AUSERTOGROUP":
            if (!checkCmd(args, 2, "Usage: AUSERTOGROUP <USER> <GROUP>", true))
                return CommandResult.ARGS;
            user = args.nextToken();
            group = args.nextToken();
            if(g_cli.addUserToGroup(user, group, token)) {
                System.out.printf("Added user %s to group %s\n", user, group);
            }
            break;
        case "RUSERFROMGROUP":
            if (!checkCmd(args, 2, "Usage: RUSERTOGROUP <USER> <GROUP>", true))
                return CommandResult.ARGS;
            user = args.nextToken();
            group = args.nextToken();
            if(g_cli.deleteUserFromGroup(user, group, token)) {
                System.out.printf("Removed user %s from group %s\n", user, group);
            }
            break;
        case "UPLOADF":
            if (!checkCmd(args, 3, "Usage: UPLOADF <SRC-FILE> <DST-FILE> <GROUP>", false))
                return CommandResult.ARGS;
            src_file = args.nextToken();
            dst_file = args.nextToken();
            group = args.nextToken();
            if(f_cli.upload(src_file, dst_file, group, token))
                System.out.printf("Uploaded file %s to %s in group %s\n", src_file, dst_file, group);
            break;
        case "LFILES":
            if (!checkCmd(args, 0, "Usage: LFILES", false))
                return CommandResult.ARGS;
            List<String> files = f_cli.listFiles(token);

            if (files != null) {
                if(files.size()>0){
                    System.out.printf("Here are the files available to %s:\n", token.getSubject());
                    for(int index=0; index < files.size(); index++) {
                        System.out.printf("\t%s\n", files.get(index));
                    }
                } else {
                    System.out.printf("There are no files available to %s\n", token.getSubject());
                }
            }
            break;
        case "DOWNLOADF":
            if (!checkCmd(args, 2, "Usage: DOWNLOADF <SRC-FILE> <DST-FILE>", false))
                return CommandResult.ARGS;
            src_file = args.nextToken();
            dst_file = args.nextToken();
            if(f_cli.download(src_file, dst_file, token))
                System.out.printf("Downloaded file %s into %s\n", src_file, dst_file);
            break;
        case "DELETEF":
            System.out.println("TEST");
            if (!checkCmd(args, 1, "Usage: DELETEF <FILENAME>", false))
                return CommandResult.ARGS;
            src_file = args.nextToken();
            if(f_cli.delete(src_file, token))
                System.out.printf("Deleted file %s\n", src_file);
            break;
        default:
            return CommandResult.NOTCMD;
        }

        return CommandResult.SUCCESS;
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
        case "STATUS":
            connectionStatus();
            printToken();
            break;
        case "EXIT":
            if (g_cli.isConnected())
                g_cli.disconnect();
            if (f_cli.isConnected())
                f_cli.disconnect();
            return false;

        case "GET":
            getToken(cmds);
            break;
        default:
            // Handle as Group Command or File Command
            if(mapServerCommand(cmd, cmds) == CommandResult.NOTCMD) {
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