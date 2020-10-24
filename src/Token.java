import java.util.List;
import java.util.ArrayList;
class Token implements UserToken, java.io.Serializable
{
    private static final long serialVersionUID = 4600343803563417992L;
	private String issuer;
	private String subject;
	private List<String> groups;
	private List<String> shownGroups;

	private String passwordSecret;

	public Token(String inIssuer, String inSubject, ArrayList<String> inGroup, String passSecret)
	{
		issuer=inIssuer;
		subject=inSubject;
		groups=inGroup;
		shownGroups=new ArrayList<String>();
		passwordSecret=passSecret;
	}

	public Token(String inIssuer, String inSubject, ArrayList<String> inGroup, ArrayList<String> inShown, String passSecret)
	{
		issuer=inIssuer;
		subject=inSubject;
		groups=inGroup;
		shownGroups=inShown;
		passwordSecret=passSecret;
	}

	public Token()
	{
		issuer=null;
		subject=null;
		groups=new ArrayList<String>();
		shownGroups=new ArrayList<String>();
		passwordSecret=null;
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
	{	if(!groups.contains(toAdd))
			return groups.add(toAdd);
		return false;
	}

	public boolean removeFromGroup(String toRemove)
	{
		if(groups.contains(toRemove)) {
			if(shownGroups.contains(toRemove)) {
				shownGroups.remove(toRemove);
			}
			return groups.remove(toRemove);
		}
		return false;
	}

	public boolean addToShown(String toAdd)
	{
		if(!shownGroups.contains(toAdd))
			return shownGroups.add(toAdd);
		return false;
	}

	public boolean removeFromShown(String toRemove)
	{
		if(shownGroups.contains(toRemove)){
			return groups.remove(toRemove);
		}
		return false;
	}

    public String getIssuer()
    {
    	return issuer;
    }

    public String getSubject()
    {
    	return subject;
    }

    public List<String> getGroups()
    {
    	return new ArrayList<String>(groups);
    }

    public List<String> getShownGroups()
    {
    	return new ArrayList<String>(shownGroups);
    }

    public void setPasswordSecret(String newSecret)
    {
    	passwordSecret=newSecret;
    }

    public String getPasswordSecret()
    {
    	return passwordSecret;
    }
}