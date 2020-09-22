import java.util.List;
class Token implements UserToken
{
	private String issuer;
	private String subject;
	private List<String> groups;

	public Token(String inIssuer, String inSubject, List<String> inGroup)
	{
		issuer=inIssuer;
		subject=inSubject
		groups=inGroup;
	}

	public Token()
	{
		issuer=null;
		subject=null
		groups=new List<String>();
	}

	public void setIssuer(String inIssuer)
	{
		issuer=inIssuer;
	}

	public void setSubject(String inSubject)
	{
		subject=inSubject;
	}

	public boolean addToGroup(String toAdd)
	{
		return groups.add(toAdd)
	}

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
    public String getIssuer()
    {
    	return issuer;
    }


    /**
     * This method should return a string indicating the name of the
     * subject of the token.  For instance, if "Alice" requests a
     * token from the group server "Server1", this method will return
     * the string "Alice".
     *
     * @return The subject of this token
     *
     */
    public String getSubject()
    {
    	return subject;
    }


    /**
     * This method extracts the list of groups that the owner of this
     * token has access to.  If "Alice" is a member of the groups "G1"
     * and "G2" defined at the group server "Server1", this method
     * will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    public List<String> getGroups()
    {
    	return groups;
    }
}