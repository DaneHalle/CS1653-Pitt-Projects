import java.util.Hashtable;
import java.util.Set;
import java.util.Iterator;

import java.util.Enumeration;

public class PublicKeyList implements java.io.Serializable {
    
    private static final long serialVersionUID = 7600343803563417992L;
    private Hashtable<String, PublicKeyItem> publicKeys = new Hashtable<String, PublicKeyItem>();
    
    public void addKey(String url, String ip, String key) {
        PublicKeyItem pk = new PublicKeyItem(url, ip);
        publicKeys.put(key, pk);
    }

    public boolean checkKey(String key) {
        if(publicKeys.containsKey(key)) {
            return true;
        } else {
            return false;
        }
    }

    public boolean isEmpty() {
        return publicKeys.isEmpty();
    }

    public String toString() {
        String str = "";
        Set<String> keys = publicKeys.keySet();
        Iterator<String> itr = keys.iterator();

        while (itr.hasNext()) {
            String pk = itr.next();
            PublicKeyItem item = publicKeys.get(pk);
            str += item.getUrl() + "," + item.getIp() + " " + pk + "\n";
        }

        return str;
    }

    class PublicKeyItem implements java.io.Serializable {
        
        private static final long serialVersionUID = -6699986336399821598L;
        private String url;
        private String ip;

        public PublicKeyItem(String new_url, String new_ip) {
            url = new_url;
            ip = new_ip;
        }

        public void setUrl(String new_url) {
            url = new_url;
        }

        public void setIp(String new_ip) {
            ip = new_ip;
        }

        public String getUrl() {
            return url;
        }

        public String getIp() {
            return ip;
        }
    }
}