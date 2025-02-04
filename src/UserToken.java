
import java.util.List;

import javax.crypto.*;

/**
 * A simple interface to the token data structure that will be
 * returned by a group server.
 *
 * You will need to develop a class that implements this interface so
 * that your code can interface with the tokens created by your group
 * server.
 *
 */
public interface UserToken {
    /**
     * This method should return a string describing the issuer of
     * this token.  This string identifies the group server that
     * created this token.  For instance, if "Alice" requests a token
     * from the group server "Server1", this method will return the
     * string "Server1".
     *
     * @return The issuer of this token
     *
     */
    public String getIssuer();


    /**
     * This method should return a string indicating the name of the
     * subject of the token.  For instance, if "Alice" requests a
     * token from the group server "Server1", this method will return
     * the string "Alice".
     *
     * @return The subject of this token
     *
     */
    public String getSubject();


    /**
     * This method extracts the list of groups that the owner of this
     * token has access to.  If "Alice" is a member of the groups "G1"
     * and "G2" defined at the group server "Server1", this method
     * will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    public List<String> getGroups();

    public boolean addToGroup(String name);

    public boolean removeFromGroup(String name);

    public boolean addToShown(String name);

    public boolean removeFromShown(String name);

    public List<String> getShownGroups();

    // Cryptography
    public void setPasswordSecret(String newSecret);

    public String getPasswordSecret();

    // Token Integrity
    public byte[] getPublicKey();

    public byte[] getSignature();

    public String getPublicKeyEncoded();

    public String getSignatureEncoded();

    public boolean verify();

}   //-- end interface UserToken
