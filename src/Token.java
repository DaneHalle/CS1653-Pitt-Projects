import java.util.List;
import java.util.ArrayList;
class Token implements UserToken, java.io.Serializable
{
    private static final long serialVersionUID = 4600343803563417992L;
	private String issuer;
	private String subject;
	private List<String> groups;
	private List<String> shownGroups;

	public Token(String inIssuer, String inSubject, ArrayList<String> inGroup)
	{
		issuer=inIssuer;
		subject=inSubject;
		groups=inGroup;
		shownGroups=new ArrayList<String>();
	}

	public Token(String inIssuer, String inSubject, ArrayList<String> inGroup, ArrayList<String> inShown)
	{
		issuer=inIssuer;
		subject=inSubject;
		groups=inGroup;
		shownGroups=inShown;
	}

	public Token()
	{
		issuer=null;
		subject=null;
		groups=new ArrayList<String>();
		shownGroups=new ArrayList<String>();
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
		return groups.add(toAdd);
	}

	public boolean removeFromGroup(String toRemove)
	{
		if(groups.contains(toRemove)) {
			return groups.remove(toRemove);
		}
		return false;
	}

	public boolean addToShown(String toAdd)
	{
		return shownGroups.add(toAdd);
	}

	public boolean removeFromShown(String toRemove)
	{
		if(shownGroups.contains(toRemove)){
			System.out.println("AAAAAAAAA");
			return groups.remove(toRemove);
		}
		System.out.println("BBBBBBBBB");
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
}