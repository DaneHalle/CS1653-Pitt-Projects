/* This list represents the users on the server */
import java.util.ArrayList;
import java.util.Hashtable;

import java.util.Enumeration;

public class UserList implements java.io.Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 7600343803563417992L;
    private Hashtable<String, User> list = new Hashtable<String, User>();

    public synchronized void addUser(String username) {
        User newUser = new User();
        list.put(username, newUser);
    }

    public synchronized void deleteUser(String username) {
        list.remove(username);
    }

    public synchronized boolean checkUser(String username) {
        if(list.containsKey(username)) {
            return true;
        } else {
            return false;
        }
    }

    public synchronized ArrayList<String> getUserGroups(String username) {
        return list.get(username).getGroups();
    }

    public synchronized ArrayList<String> getUserOwnership(String username) {
        return list.get(username).getOwnership();
    }

    public synchronized ArrayList<String> getShown(String username) {
        return list.get(username).getShown();
    }

    public synchronized void addGroup(String user, String groupname) {
        list.get(user).addGroup(groupname);
    }

    public synchronized void removeGroup(String user, String groupname) {
        list.get(user).removeGroup(groupname);
    }

    public synchronized void addOwnership(String user, String groupname) {
        list.get(user).addOwnership(groupname);
    }

    public synchronized void removeOwnership(String user, String groupname) {
        list.get(user).removeOwnership(groupname);
    }

    public synchronized void addShown(String user, String groupname) {
        list.get(user).addShown(groupname);
    }

    public synchronized void removeShown(String user, String groupname) {
        list.get(user).removeShown(groupname);
    }

    /**
     * Function to get all groups accessible to any given user. To be used by 
     * groupList. 
     *
     * @return ArrayList<String> of all groups accessible to users within the Server
     */
    public synchronized ArrayList<String> getAllUsers() {
        ArrayList<String> out = new ArrayList<String>();
        Enumeration<String> enumeration = list.keys();

        while(enumeration.hasMoreElements()){
            String key = enumeration.nextElement();
            out.add(key);
        }
        return out;
    }


    class User implements java.io.Serializable {

        /**
         *
         */
        private static final long serialVersionUID = -6699986336399821598L;
        private ArrayList<String> groups;
        private ArrayList<String> ownership; // this is there own group
        private ArrayList<String> shown;

        public User() {
            groups = new ArrayList<String>();
            ownership = new ArrayList<String>();
            shown = new ArrayList<String>();
        }

        public ArrayList<String> getGroups() {
            return groups;
        }

        public ArrayList<String> getOwnership() {
            return ownership;
        }

        public ArrayList<String> getShown() {
            return shown;
        }

        public void addGroup(String group) {
            groups.add(group);
        }

        public void removeGroup(String group) {
            if(!groups.isEmpty()) {
                if(groups.contains(group)) {
                    groups.remove(groups.indexOf(group));
                }
            }
        }

        public void addOwnership(String group) {
            ownership.add(group);
        }

        public void removeOwnership(String group) {
            if(!ownership.isEmpty()) {
                if(ownership.contains(group)) {
                    ownership.remove(ownership.indexOf(group));
                }
            }
        }

        public void addShown(String group) {
            shown.add(group);
        }

        public void removeShown(String group) {
            if(!shown.isEmpty()) {
                if(shown.contains(group)) {
                    shown.remove(shown.indexOf(group));
                }
            }
        }
    }

}
