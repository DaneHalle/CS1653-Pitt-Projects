/* This list represents the groups on the server */
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Set;
import java.util.Enumeration;

public class GroupList implements java.io.Serializable {
    
    /*
     *
     */
    private static final long serialVersionUID = 6600343803563417992L;
    private Hashtable<String, Group> list = new Hashtable<String, Group>();

    public GroupList(UserList ul) {
        ArrayList<String> users = ul.getAllUsers();

        for(int i=0; i < users.size(); i++) {
            ArrayList<String> ownership = ul.getUserOwnership(users.get(i));
            ArrayList<String> groups = ul.getUserGroups(users.get(i));
            // Get all the ownerships from the user
            for(int j=0; j < ownership.size(); j++) {
                Group group = list.get(ownership.get(j));
                if (group == null) {
                    // If group does not exist create new one with user
                    list.put(ownership.get(j), new Group(users.get(i)));
                } else {
                    // If it does exist set the user to the owner
                    group.setOwner(users.get(i));
                }
            }
            for(int j=0; j < groups.size(); j++) {
                Group group = list.get(groups.get(j));
                if (ownership.contains(groups.get(j))){
                    continue;
                }
                if (group == null) {
                    // Create a new group with no owner
                    Group new_group = new Group();
                    list.put(groups.get(j), new_group);
                    // Add user to the group
                    new_group.addUser(users.get(i));
                } else {
                    // Group exists so add user to it
                    group.addUser(users.get(i));
                }
            }
        }
    }

    public synchronized void addGroup(String group, String owner) {
        Group newGroup = new Group(owner);
        list.put(group, newGroup);
    }

    public synchronized void deleteGroup(String group) {
        list.remove(group);
    }

    public synchronized boolean checkGroup(String group) {
        if(list.containsKey(group)) {
            return true;
        } else {
            return false;
        }
    }

    public synchronized ArrayList<String> getGroupUsers(String groupname) {
        return list.get(groupname).getUsers();
    }

    public synchronized String getGroupOwner(String group) {
        return list.get(group).getOwner();
    }

    public synchronized void addMember(String username, String groupname) {
        list.get(groupname).addUser(username);
    }

    public synchronized void removeMember(String username, String groupname) {
        list.get(groupname).removeUser(username);
    }


    class Group implements java.io.Serializable {
        private static final long serialVersionUID = -6699986336399821598L;
        private ArrayList<String> users;
        private String owner;

        public Group() {
            users = new ArrayList<String>();
            owner = null;
        }

        public Group(String new_owner) {
            users = new ArrayList<String>();
            owner = new_owner;
        }

        public ArrayList<String> getUsers() {
            return users;
        }

        public String getOwner() {
            if (owner == null)
                System.out.println("WARNING:Owner not set");
            return owner;
        }

        public void addUser(String user) {
            users.add(user);
        }

        public void removeUser(String user) {
            if(!users.isEmpty()) {
                if(users.contains(user)) {
                    users.remove(users.indexOf(user));
                }
            }
        }

        void setOwner(String new_owner) {
            owner = new_owner;
        }
    }
}