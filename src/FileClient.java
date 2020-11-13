/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.ArrayList;

public class FileClient extends Client implements FileClientInterface {

    public boolean delete(String filename, UserToken token) {
        String remotePath;
        if (filename.charAt(0)=='/') {
            remotePath = filename.substring(1);
        } else {
            remotePath = filename;
        }
        Envelope env = new Envelope("DELETEF"); //Success
        env.addObject(remotePath);
        env.addObject(token);
        try {
            output.writeObject(env);
            env = (Envelope)input.readObject();

            if (env.getMessage().compareTo("OK")==0) {
                System.out.printf("File %s deleted successfully\n", filename);
            } else {
                System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
                try {
                    System.out.printf("%s\n", env.getObjContents().get(0));
                } catch (Exception e) {
                }
                return false;
            }
        } catch (IOException e1) {
            e1.printStackTrace();
        } catch (ClassNotFoundException e1) {
            e1.printStackTrace();
        }

        return true;
    }

    public String[] download(String sourceFile, String destFile, UserToken token) {
        if (sourceFile.charAt(0)=='/') {
            sourceFile = sourceFile.substring(1);
        }

        File file = new File(destFile);
        String[] out = new String[2];
        try {


            if (!file.exists()) {
                file.createNewFile();
                FileOutputStream fos = new FileOutputStream(file);

                Envelope env = new Envelope("DOWNLOADF"); //Success
                env.addObject(sourceFile);
                env.addObject(token);
                output.writeObject(env);

                env = (Envelope)input.readObject();

                while (env.getMessage().compareTo("CHUNK")==0) {
                    fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
                    System.out.printf(".");
                    env = new Envelope("DOWNLOADF"); //Success
                    output.writeObject(env);
                    env = (Envelope)input.readObject();
                }
                fos.close();

                if(env.getMessage().compareTo("EOF")==0) {
                    fos.close();
                    System.out.printf("\nTransfer successful file %s\n", sourceFile);
                    out[0] = (String)env.getObjContents().get(0);
                    out[1] = (String)env.getObjContents().get(1);

                    env = new Envelope("OK"); //Success
                    output.writeObject(env);
                } else {
                    System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
                    file.delete();
<<<<<<< HEAD
                    return false;
=======
                    System.out.printf("%s\n", env.getObjContents().get(0));
                    return null;
>>>>>>> 20a0f3fadf47f02ee2236532171bab1f4ccfd9bb
                }
            }

            else {
                System.out.printf("Error couldn't create file %s\n", destFile);
                return null;
            }


        } catch (IOException e1) {

            System.out.printf("Error couldn't create file %s\n", destFile);
            return null;


        } catch (ClassNotFoundException e1) {
            e1.printStackTrace();
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    public List<String> listFiles(UserToken token) {
        try {
            Envelope message = null, env = null;
            //Tell the server to return the member list
            message = new Envelope("LFILES");
            message.addObject(token); //Add requester's token
            output.writeObject(message);

            env = (Envelope)input.readObject();

            //If server indicates success, return the member list
            if(env.getMessage().equals("OK")) {
                List<String> toReturn = new ArrayList<String>();
                for(int index = 0; index < env.getObjContents().size(); index++) {
                    String toAdd = (String)env.getObjContents().get(index);
                    if(!toReturn.contains(toAdd)) {
                        toReturn.add(toAdd);
                    }
                }
                return toReturn;
                // return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
            }
            System.out.printf("%s\n", env.getObjContents().get(0));

            return null;

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    public List<String> listFilesForGroup(String group, UserToken token) {
        try {
            Envelope message = null, env = null;
            //Tell the server to return the member list
            message = new Envelope("LFORGROUP");
            message.addObject(group);
            message.addObject(token); //Add requester's token
            output.writeObject(message);

            env = (Envelope)input.readObject();

            //If server indicates success, return the member list
            if(env.getMessage().equals("OK")) {
                List<String> toReturn = new ArrayList<String>();
                for(int index = 0; index < env.getObjContents().size(); index++) {
                    String toAdd = (String)env.getObjContents().get(index);
                    if(!toReturn.contains(toAdd)) {
                        toReturn.add(toAdd);
                    }
                }
                return toReturn;
                // return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
            }
            System.out.printf("%s\n", env.getObjContents().get(0));

            return null;

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }

    public boolean upload(String sourceFile, String destFile, String group,
                          UserToken token, String id) {

        if (destFile.charAt(0)!='/') {
            destFile = "/" + destFile;
        }

        try {

            Envelope message = null, env = null;
            //Tell the server to return the member list
            message = new Envelope("UPLOADF");
            message.addObject(destFile);
            message.addObject(group);
            message.addObject(token); //Add requester's token
            message.addObject(id);
            output.writeObject(message);


            FileInputStream fis = new FileInputStream(sourceFile);

            env = (Envelope)input.readObject();

            //If server indicates success, return the member list
            if(env.getMessage().equals("READY")) {
                System.out.printf("Meta data upload successful\n");

            } else {
                System.out.printf("Upload failed: %s\n", env.getMessage());
                System.out.printf("%s\n", env.getObjContents().get(0));
                return false;
            }


            do {
                byte[] buf = new byte[4096];
                if (env.getMessage().compareTo("READY")!=0) {
                    System.out.printf("Server error: %s\n", env.getMessage());
                    return false;
                }
                message = new Envelope("CHUNK");
                int n = fis.read(buf); //can throw an IOException
                if (n > 0) {
                    System.out.printf(".");
                } else if (n < 0) {
                    System.out.println("Read error");
                    System.out.printf("FAILED: %s\n", env.getObjContents().get(0));
                    return false;
                }

                message.addObject(buf);
                message.addObject(Integer.valueOf(n));

                output.writeObject(message);


                env = (Envelope)input.readObject();


            } while (fis.available()>0);

            //If server indicates success, return the member list
            if(env.getMessage().compareTo("READY")==0) {

                message = new Envelope("EOF");
                output.writeObject(message);

                env = (Envelope)input.readObject();
                if(env.getMessage().compareTo("OK")==0) {
                    System.out.printf("\nFile data upload successful\n");
                } else {

                    System.out.printf("\nUpload failed: %s\n", env.getMessage());
                    System.out.printf("FAILED: %s\n", env.getObjContents().get(0));
                    return false;
                }

            } else {

                System.out.printf("Upload failed: %s\n", env.getMessage());
                System.out.printf("FAILED: %s\n", env.getObjContents().get(0));
                return false;
            }

        } catch(Exception e1) {
            System.err.println("Error: " + e1.getMessage());
            e1.printStackTrace(System.err);
            return false;
        }
        return true;
    }

    public void printPublicKeys() {
        if(publicKeyList == null) {
            readPublicKeyList();
        }

        if (publicKeyList.isEmpty()) {
                System.out.println("No public keys have been stored.");
        } else {
            System.out.println("Public Keys:");
            System.out.println(publicKeyList);
        }
    }
}

