import java.util.StringTokenizer;
import java.util.ArrayList;
import java.util.List;
import java.io.BufferedReader;      // Needed to read from the console
import java.io.InputStreamReader;   // Needed to read from the console
import java.lang.UnsupportedOperationException;

// Crypto libraries
import org.bouncycastle.*;
import org.bouncycastle.jce.provider.*;
import org.bouncycastle.jce.*;
import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPublicKey;

import javax.crypto.KeyAgreement;

public class RunClient {
    private GroupClient g_cli;
    private FileClient f_cli;
    private UserToken token;

    private Key group_key; // may change to key
    private KeyPair rsa_key;

    private boolean gui = false;

    public RunClient() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        g_cli = new GroupClient(false);
        f_cli = new FileClient();
        rsa_key = g_cli.generateRSA(); // could also be g_cli
    }

    public RunClient(boolean _gui) {
        gui = _gui;
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        g_cli = new GroupClient(gui);
        f_cli = new FileClient();
        rsa_key = g_cli.generateRSA(); // could also be g_cli
    }

    private enum CommandResult {
        NOTCMD,
        ARGS,
        SUCCESS,
        FNOT, 
        GNOT,
        FAIL
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
                // TODO: Change username
                g_cli.verifyServer("GROUP");
                break;            
            case "FILE":
                f_cli.connect(server, port);
                f_cli.keyExchange("FILE", rsa_key, gui);
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

        if(token != null) {
            if (token.verify()) {
                System.out.println("SUCCESS: Token is valid");
            } else {
                System.out.println("FAILED: Token is invalid");
            }
        }
    }

    public void printToken() {
        if(token==null) {
            System.out.println("No token exists for the current client.");
        } else {
            System.out.println("Issuer: " + token.getIssuer());
            System.out.println("Subject: " + token.getSubject());
            List<String> groups = token.getGroups();
            List<String> shownGroups = token.getShownGroups();
            System.out.println("All Groups: ");
            for(int i=0; i < groups.size(); i++) {
                System.out.println(" - " + groups.get(i));
            }

            System.out.println("Shown Groups: ");
            for(int i=0; i < shownGroups.size(); i++) {
                System.out.println(" - " + shownGroups.get(i));
            }
        }
    }

    public void help() {
        System.out.println("Here are the commands that are accessible to you.");
        String g_connection = g_cli.isConnected() ? "" : "\tCONNECT group <IP> <PORT> - connects to the group server at the given \n\t\tIP and PORT\n";
        String f_connection = f_cli.isConnected() ? "" : "\tCONNECT file <IP> <PORT> - connects to the file server at the given \n\t\tIP and PORT\n";
        System.out.print(g_connection+""+f_connection);
        if(token==null){
            System.out.println("\tNo token exists for the current client.\n\t\tGET <USER> <PASS> - gets the token for the given USER with the PASS being used for authentication");
        }else{
            String admin=token.getShownGroups().contains("ADMIN") ? "\tCUSER <USER> <TEMP_PASS>- creates a user with the given USERname and TEMProary PASSword\n\tDUSER <USER> - deletes a user with the given USERname\n" : "";
            System.out.print(admin);
            String groups="\tCGROUP <GROUPNAME> - creates a group with the given \n\t\tGROUPNAME\n\tDGROUP <GROUPNAME> - deletes a group with the given \n\t\tGROUPNAME should you be owner\n";
            System.out.print(groups);
            String management=token.getShownGroups().size()>0 ? "\tAUSERTOGROUP <USER> <GROUPNAME> - adds USER to group \n\t\tGROUPNAME if you are owner of GROUPNAME\n\tRUSERFROMGROUP <USER> <GROUPNAME> - removes USER from \n\t\tgroup GROUPNAME if you are the owner of GROUPNAME\n" : "";
            System.out.print(management);
            String file=token.getShownGroups().size()>0 ? "\tLFILES - lists all files accessible to you\n\tUPLOADF <src_file> <dest_file> <GROUPNAME> - uplaods local src_file \n\t\tto GROUPNAME under name of dest_file\n\tDOWNLOADF <src_file> <dest_file> - downloads src_file \n\t\tfrom server to local file name dest_file\n\tDELETEF <file> - deletes file from the server\n\tPUBLICK - shows the public keys of file servers client has connected to\n" : "";
            System.out.print(file);
            String least=token.getGroups().size()>0 ? "\tSHOW <GROUPNAME> - Adds GROUPNAME to scope to allow \n\t\tcommands and management\n\tSHOWALL - Adds all available groups to scope to allow \n\t\tcommands and management\n\tHIDE <GROUPNAME> - Removes GROUPNAME from scope to disallow \n\t\tcommands and management\n\tHIDEALL - Removes all available groups from scope to disallow \n\t\tcommands and management\n" : "";
            System.out.print(least);
        }
        System.out.println("\tHELP - shows available commands to you dynamically\n\tEXIT - disconnects the client from any server they are connected to and \n\t\tends the program");
    }

    private boolean getToken(StringTokenizer args) {
        if (args.countTokens() != 2) {
            System.out.println("Usage: GET <USERNAME> <PASSWORD>");
            return false;
        } else if (!g_cli.isConnected()) {
            System.out.println("Group server is not connected");
            return false;
        }

        token = g_cli.getToken(args.nextToken(), args.nextToken());
        
        if(token == null) {
            System.out.println("Failed to retrieve token");
            return false;
        }

        System.out.println("Successfully retrieved token");
        return true;
    }

    private void corruptToken() {
        if (token == null)
            return;
        
        // Modify the data
        token.addToGroup("corrupted");
        
        if (token.verify()) {
            System.out.println("VERIFIED");
        } else {
            System.out.println("ERROR INVALID");
        }

        printToken();
    }

    public List<String> getUnShownGroups() {
        List<String> out = new ArrayList<String>();
        List<String> allGroups = token.getGroups();
        List<String> shownGroups = token.getShownGroups();
        for(int index = 0; index < allGroups.size(); index++) {
            if (!shownGroups.contains(allGroups.get(index))) {
                out.add(allGroups.get(index));
            }
        }
        return out;
    }

    public List<String> getShownGroups() {
        return token.getShownGroups();
    }

    public List<String> getFilesForGroup(String group) {
        if (!f_cli.isConnected()) 
            return null;
        return f_cli.listFilesForGroup(group, token);
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

        return true;
    }

    private CommandResult mapServerCommand(String cmd, StringTokenizer args) {
        // For the group server
        String user;
        
        // For the file server
        String src_file;
        String dst_file;
        String group;
        String pass;

        boolean groupConnected=g_cli.isConnected();
        boolean fileConnected=f_cli.isConnected();
        
        // TODO: Try to add corruptToken to each instruction
        switch(cmd) {
            case "CU":
            case "CUSER":
                if (!groupConnected) 
                    return CommandResult.GNOT;
                if (!checkCmd(args, 2, "Usage: CUSER <USER> <TEMP_PASS>", true))
                    return CommandResult.ARGS;
                user = args.nextToken();
                pass = args.nextToken();
                if(g_cli.createUser(user, token, pass))
                    System.out.printf("Created user: %s\n", user);
                else
                    return CommandResult.FAIL;
                break;
            case "DU":
            case "DUSER":
                if (!groupConnected) 
                    return CommandResult.GNOT;
                if (!checkCmd(args, 1, "Usage: DUSER <USER>", true))
                    return CommandResult.ARGS;
                user = args.nextToken();
                if(g_cli.deleteUser(user, token))
                    System.out.printf("Deleted user: %s\n", user);
                else
                    return CommandResult.FAIL;
                break;
            case "CG":
            case "CGROUP":
                if (!groupConnected) 
                    return CommandResult.GNOT;
                if (!checkCmd(args, 1, "Usage: CGROUP <GROUP>", true))
                    return CommandResult.ARGS;
                group = args.nextToken();
                if(g_cli.createGroup(group, token))
                    System.out.printf("Created group: %s\n", group);
                else
                    return CommandResult.FAIL;
                break;
            case "DG":
            case "DGROUP":
                if (!groupConnected) 
                    return CommandResult.GNOT;
                if (!checkCmd(args, 1, "Usage: DGROUP <GROUP>", true))
                    return CommandResult.ARGS;
                group = args.nextToken();
                if(g_cli.deleteGroup(group, token))
                    System.out.printf("Deleted group: %s\n", group);
                else
                    return CommandResult.FAIL;
                break;
            case "LM":
            case "LMEMBERS":
                if (!groupConnected) 
                    return CommandResult.GNOT;
                if (!checkCmd(args, 1, "Usage: LMEMBERS <GROUP>", true))
                    return CommandResult.ARGS;
                group = args.nextToken();
                List<String> members = g_cli.listMembers(group, token);
                if (members != null) {
                    System.out.printf("Here are the members within group %s:\n", group);
                    for(int index=0; index < members.size(); index++) {
                        System.out.printf("\t%s\n", members.get(index));
                    }
                } else {
                    return CommandResult.FAIL;
                }
                break;
            case "A":
            case "AUTG":
            case "AUSERTOGROUP":
                if (!groupConnected) 
                    return CommandResult.GNOT;
                if (!checkCmd(args, 2, "Usage: AUSERTOGROUP <USER> <GROUP>", true))
                    return CommandResult.ARGS;
                user = args.nextToken();
                group = args.nextToken();
                if(g_cli.addUserToGroup(user, group, token)) 
                    System.out.printf("Added user %s to group %s\n", user, group);
                else
                    return CommandResult.FAIL;
                break;
            case "R":
            case "RUFG":
            case "RUSERFROMGROUP":
                if (!groupConnected) 
                    return CommandResult.GNOT;
                if (!checkCmd(args, 2, "Usage: RUSERTOGROUP <USER> <GROUP>", true))
                    return CommandResult.ARGS;
                user = args.nextToken();
                group = args.nextToken();
                if(g_cli.deleteUserFromGroup(user, group, token)) 
                    System.out.printf("Removed user %s from group %s\n", user, group);
                else
                    return CommandResult.FAIL;
                break;
            case "U":
            case "UF":
            case "UPLOADF":
                if (!fileConnected) 
                    return CommandResult.FNOT;
                if (!checkCmd(args, 3, "Usage: UPLOADF <SRC-FILE> <DST-FILE> <GROUP>", false))
                    return CommandResult.ARGS;
                src_file = args.nextToken();
                dst_file = args.nextToken();
                group = args.nextToken();
                if(f_cli.upload(src_file, dst_file, group, token))
                    System.out.printf("Uploaded file %s to %s in group %s\n", src_file, dst_file, group);
                else
                    return CommandResult.FAIL;
                break;
            case "LF":
            case "LFILES":
                if (!fileConnected) 
                    return CommandResult.FNOT;
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
                } else {
                    return CommandResult.FAIL;
                }
                break;
            case "DOWN":
            case "DOWNLOADF":
                if (!fileConnected) 
                    return CommandResult.FNOT;
                if (!checkCmd(args, 2, "Usage: DOWNLOADF <SRC-FILE> <DST-FILE>", false))
                    return CommandResult.ARGS;
                src_file = args.nextToken();
                dst_file = args.nextToken();
                if(f_cli.download(src_file, dst_file, token))
                    System.out.printf("Downloaded file %s into %s\n", src_file, dst_file);
                else
                    return CommandResult.FAIL;
                break;
            case "DELETE":
            case "DELETEF":
                if (!fileConnected) 
                    return CommandResult.FNOT;
                if (!checkCmd(args, 1, "Usage: DELETEF <FILENAME>", false))
                    return CommandResult.ARGS;
                src_file = args.nextToken();
                if(f_cli.delete(src_file, token))
                    System.out.printf("Deleted file %s\n", src_file);
                else
                    return CommandResult.FAIL;
                break;
            case "PUB":
            case "PUBLICK":
                f_cli.printPublicKeys();
                break;
            case "S":
            case "SHOW":
                if (!groupConnected)
                    return CommandResult.GNOT;
                if (!checkCmd(args, 1, "Usage: SHOW <GROUP-NAME>", true))
                    return CommandResult.ARGS;
                group = args.nextToken();
                if(g_cli.showGroup(group, token))
                    System.out.printf("Added %s to list of Shown Groups\n", group);
                else
                    return CommandResult.FAIL;
                break;
            case "SA":
            case "SHOWALL":
                if (!groupConnected)
                    return CommandResult.GNOT;
                if (!checkCmd(args, 0, "Usage: SHOWALL", true))
                    return CommandResult.ARGS;
                if(g_cli.showAll(token))
                    System.out.printf("Added all groups to list of Shown Groups\n");
                else
                    return CommandResult.FAIL;
                break;
            case "H":
            case "HIDE":
                if (!groupConnected)
                    return CommandResult.GNOT;
                if (!checkCmd(args, 1, "Usage: HIDE <GROUP-NAME>", true))
                    return CommandResult.ARGS;
                group = args.nextToken();
                if(g_cli.hideGroup(group, token))
                    System.out.printf("Hidden %s to list of Shown Groups\n", group);
                else
                    return CommandResult.FAIL;
                break;
            case "HA":
            case "HIDEALL":
                if (!groupConnected)
                    return CommandResult.GNOT;
                if (!checkCmd(args, 0, "Usage: HIDEALL", true))
                    return CommandResult.ARGS;
                if(g_cli.hideAll(token))
                    System.out.printf("Hiden all groups to list of Shown Groups\n");
                else
                    return CommandResult.FAIL;
                break;
            case "LFFG":
            case "LFILESFORGROUP":
                if (!fileConnected) 
                    return CommandResult.FNOT;
                if (!checkCmd(args, 1, "Usage: LFILESFORGROUP", false))
                    return CommandResult.ARGS;
                group=args.nextToken();
                List<String> gFiles = f_cli.listFilesForGroup(group, token);
                if (gFiles != null) {
                    if(gFiles.size()>0){
                        System.out.printf("Here are the files available to %s:\n", token.getSubject());
                        for(int index=0; index < gFiles.size(); index++) {
                            System.out.printf("\t%s\n", gFiles.get(index));
                        }
                    } else {
                        System.out.printf("There are no files available to %s\n", token.getSubject());
                    }
                } else {
                    return CommandResult.FAIL;
                }
                break;
            default:
                return CommandResult.NOTCMD;
        }
        // Successful Command, then refresh token with current token
        return CommandResult.SUCCESS;
    }

    public boolean mapCommand(StringTokenizer cmds) {
        if (!cmds.hasMoreTokens()) {
            return true;
        }
        String preformat = cmds.nextToken();
        String cmd = preformat.toUpperCase();

        if (token!=null) {
            token = g_cli.refreshToken(token);
        }

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
            case "HELP":
                help();
                break;
            default:
                // Handle as Group Command or File Command
                if(token==null){
                    System.out.println("You need to GET a token first");
                    break;
                }
                CommandResult res = mapServerCommand(cmd, cmds);
                if(res == CommandResult.NOTCMD) {
                    System.out.printf("Command %s does not exist\n", preformat);
                    break;
                } else if (res == CommandResult.FNOT) {
                    System.out.println("The File Server is not connected.");
                } else if (res == CommandResult.GNOT) {
                    System.out.println("The Group Server is not connected.");
                } else if (res == CommandResult.FAIL) {
                    // System.out.printf("Unable to use command %s\n", cmd);
                }
                break;
        }

        return true;
    }

    public static void main(String args[]) {
        RunClient rcli = new RunClient();
        StringTokenizer cmd;

        do {
            System.out.println("Enter a command, or type \"EXIT\" to quit.");
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