import java.util.List;
import java.util.ArrayList;
class Token implements UserToken, java.io.Serializable
{
    private static final long serialVersionUID = 4600343803563417992L;
	private String issuer;
	private String subject;
	private List<String> groups;

	public Token(String inIssuer, String inSubject, ArrayList<String> inGroup)
	{
		issuer=inIssuer;
		subject=inSubject;
		groups=inGroup;
	}

	public Token()
	{
		issuer=null;
		subject=null;
		groups=new ArrayList<String>();
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
    	return groups;
    }
}