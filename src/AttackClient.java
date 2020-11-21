import java.util.StringTokenizer;
import java.util.ArrayList;
import java.util.List;
import java.io.BufferedReader;      // Needed to read from the console
import java.io.InputStreamReader;   // Needed to read from the console
import java.lang.UnsupportedOperationException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Base64;
import java.util.Scanner;
import java.util.Arrays;

import java.time.OffsetDateTime;

// Crypto libraries
import org.bouncycastle.*;
import org.bouncycastle.jce.provider.*;
import org.bouncycastle.jce.*;
import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPublicKey;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;

public class AttackClient {

	public static void main(String[] args) {
		// Usage | AttackClient <IP> <PORT> <USERNAME> <list> <threads>
		AttackClient ac = new AttackClient();

		if (args.length < 4) {
			System.out.println(args.length);
			return;
		} else {
			String ip = args[0];
			int port = Integer.parseInt(args[1]);
			String username = args[2];
			String list = args[3];
			int threads = Integer.parseInt(args[4]); 

            AttackClientThread thread = null;

            OffsetDateTime start = OffsetDateTime.now();

			try {
				File dictionary = new File(list);
				Scanner dictRead = new Scanner(dictionary);

				int i = 0;
				while (dictRead.hasNextLine()) {
					String tem=dictRead.nextLine();
					i++;
				}
				dictRead.close();

				dictRead = new Scanner(dictionary);
				String[] pwStore = new String[i+1];
				ArrayList<AttackClientThread> arrThreads=new ArrayList<AttackClientThread>();

				int z=0; int ct=0;
				while (dictRead.hasNextLine()) {
					String pw = dictRead.nextLine();
					pwStore[z]=pw;
					if (z%(i/threads)==0 && z!=0) {
						ct++;
						thread = new AttackClientThread(ip, port, username, Arrays.copyOfRange(pwStore, z-(i/threads), z));
						System.out.println("Trying "+z+" passwords");
            			thread.start();
            			arrThreads.add(thread);
					}
					z++;
				}

				for (int t = 0; t<arrThreads.size(); t++) {
					arrThreads.get(t).join();
				}
					// System.out.println(ct);
					// System.out.println(i);
			} catch (Exception e) {
				System.out.println(e);
			}

			OffsetDateTime end = OffsetDateTime.now();

			System.out.println("STARTED AT: \t"+start);
			System.out.println("ENDED AT:   \t"+end);

			// cain.txt - 3MB
            // Personal Machine
			// STARTED AT:     2020-11-17T20:13:10.026-05:00
			// ENDED AT:       2020-11-17T20:21:04.171-05:00
			// Total:		   7 minutes	54 seconds

            // Linux cluster
            // STARTED AT:     2020-11-20T08:43:52.798-05:00
            // ENDED AT:       2020-11-20T09:00:02.634-05:00
            // Total:          16 minutes   10 seconds

			// john.txt - 21.4KB
            // Personal Machine
			// STARTED AT:     2020-11-17T20:21:23.337-05:00
			// ENDED AT:       2020-11-17T20:24:07.937-05:00
			// Total:		   2 minutes	44 seconds

            // Linux cluster
            // STARTED AT:     2020-11-20T09:01:21.466-05:00
            // ENDED AT:       2020-11-20T09:03:01.258-05:00
            // Total:          1 minutes    40 seconds

			// PasswordPro.txt - 29.5MB
            // Personal Machine
			// STARTED AT:     2020-11-17T20:37:49.740-05:00
			// ENDED AT:       2020-11-17T20:40:25.049-05:00
			// Total:		   2 minutes	36 seconds

            // Linux cluster
            // 
            // 
            // Total:          7 minutes    54 seconds

			// phpbb.txt - 1.5MB
            // Personal Machine
			// STARTED AT:     2020-11-17T21:17:47.020-05:00
			// ENDED AT:       2020-11-17T21:22:25.276-05:00
			// Total:		   4 minutes	38 seconds

            // Linux cluster
            // STARTED AT:     2020-11-20T09:04:25.402-05:00
            // ENDED AT:       2020-11-20T09:06:24.007-05:00
            // Total:          1 minutes    59 seconds

			// rockyou.txt - 133MB
			// STARTED AT:     2020-11-17T20:40:43.088-05:00
			// ENDED AT:       2020-11-17T20:46:35.414-05:00
			// Total:		   5 minutes	52 seconds

            // Linux cluster
            // STARTED AT:     2020-11-20T09:07:29.416-05:00
            // ENDED AT:       2020-11-20T10:14:09.323-05:00
            // Total:          1 hours  6 minutes   40 seconds

			// top1000000.txt - 8.13MB
            // Personal Machine
			// STARTED AT:     2020-11-17T20:47:39.354-05:00
			// ENDED AT:       2020-11-17T21:12:15.360-05:00
			// Total:		   24 minutes	36 seconds

            // Linux cluster
            // STARTED AT:     2020-11-19T19:35:22.174-05:00
            // ENDED AT:       2020-11-19T22:35:22.647-05:00
            // Total:          3 hours
			
		}

	}
}

class AttackClientThread extends Thread{

    private AttackGroup g_cli;
    private FileClient f_cli;
    private UserToken token;

    private Key group_key; // may change to key
    private KeyPair rsa_key;

    private boolean gui = false;

    private String[] pwStore;
    private String ip;
    private int port;
    private String username;

    public AttackClientThread(String _ip, int _port, String _username, String[] _pwStore) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        g_cli = new AttackGroup(false);
        f_cli = new FileClient();
        rsa_key = g_cli.generateRSA(); // could also be g_cli

        pwStore = _pwStore;
        ip = _ip;
		port = _port;
		username = _username;
    }

    public void run() {
		StringTokenizer cmds1 = new StringTokenizer("connect group "+ip+" "+port);
		mapCommand(cmds1);

		for (int i = 0; i<pwStore.length; i++){
			StringTokenizer cmds2 = new StringTokenizer(""+username+" "+pwStore[i]);
			if(getToken(cmds2)) {
				System.out.println("Worked on ... "+pwStore[i]);
				break;
			}
			if(i%1000==0&&i!=0)
				System.out.println(Thread.currentThread().getId()+" | Done "+i);
		}
		System.out.println(Thread.currentThread().getId()+" | Finished");
		mapCommand(new StringTokenizer("exit"));
    }

    public AttackClientThread(boolean _gui) {
        gui = _gui;
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        g_cli = new AttackGroup(gui);
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
                // g_cli.verifyServer("GROUP");
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

        f_cli.fsPubKeyCheck();

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
            // System.out.println("Usage: GET <USERNAME> <PASSWORD>");
            return false;
        } else if (!g_cli.isConnected()) {
            // System.out.println("Group server is not connected");
            return false;
        }

        token = g_cli.getToken(args.nextToken(), args.nextToken());
        
        if(token == null) {
            // System.out.println("Failed to retrieve token");
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

    private void encryptFile(String src_file, String idCK, SecretKey key) {
        try {
            byte[] iv = Base64.getDecoder().decode(idCK);
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS7PADDING");
            encrypt.init(Cipher.ENCRYPT_MODE, key, ivParams);
    
            FileInputStream fileStream = new FileInputStream(new File(src_file));
            byte[] fileBytes = new byte[(int) new File(src_file).length()];
            fileStream.read(fileBytes);
    
            byte[] outputBytes = encrypt.doFinal(fileBytes);
            FileOutputStream fileOutStream = new FileOutputStream(new File(src_file+".enc"));
            fileOutStream.write(outputBytes);
            fileStream.close();
            fileOutStream.close();
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    private void decryptFile(String dst_file, String idDF, SecretKey key) {
        try {
            byte[] iv = Base64.getDecoder().decode(idDF);
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS7PADDING");
            decrypt.init(Cipher.DECRYPT_MODE, key, ivParams);
    
            FileInputStream fileStream = new FileInputStream(new File(dst_file+".enc"));
            byte[] fileBytes = new byte[(int) new File(dst_file+".enc").length()];
            fileStream.read(fileBytes);
    
            byte[] outputBytes = decrypt.doFinal(fileBytes);
            FileOutputStream fileOutStream = new FileOutputStream(new File(dst_file));
            fileOutStream.write(outputBytes);
            fileStream.close();
            fileOutStream.close();
        } catch (Exception e) {
            System.out.println(e);
        }
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
                if (!groupConnected) 
                    return CommandResult.GNOT;
                if (!fileConnected) 
                    return CommandResult.FNOT;
                if (!checkCmd(args, 3, "Usage: UPLOADF <SRC-FILE> <DST-FILE> <GROUP>", false))
                    return CommandResult.ARGS;
                src_file = args.nextToken();
                dst_file = args.nextToken();
                group = args.nextToken();

                Object[] resCK = g_cli.curKey(token, group);
                if (resCK == null) 
                    return CommandResult.FAIL;

                SecretKey currentKey = (SecretKey)resCK[0];
                String idCK = (String)resCK[1];

                encryptFile(src_file, idCK, currentKey);

                if(f_cli.upload(src_file+".enc", dst_file, group, token, idCK))
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
                if (!groupConnected) 
                    return CommandResult.GNOT;
                if (!fileConnected) 
                    return CommandResult.FNOT;
                if (!checkCmd(args, 2, "Usage: DOWNLOADF <SRC-FILE> <DST-FILE>", false))
                    return CommandResult.ARGS;
                src_file = args.nextToken();
                dst_file = args.nextToken();
                String[] resDF = f_cli.download(src_file, dst_file+".enc", token);
                if (resDF == null)
                    return CommandResult.FAIL;

                String idDF = resDF[0];
                String groupname = resDF[1];

                SecretKey key = g_cli.keyID(token, groupname, idDF);

                if (key == null) 
                    return CommandResult.FAIL;

                decryptFile(dst_file, idDF, key);
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
            token = g_cli.refreshToken(token, f_cli.getPubKey());
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
}