import java.util.List;
import java.util.ArrayList;
import java.util.Base64;
import java.lang.reflect.Field;

import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

class Token implements UserToken, java.io.Serializable
{
    private static final long serialVersionUID = 4600343803563417992L;
	private String issuer;
	private String subject;
	private List<String> groups;
	private List<String> shownGroups;

	private String passwordSecret;

	private ArrayList<String> metaVars = new ArrayList<String>();
	private String encodedPubKey;
	private String encodedSign;

	/*
	 * IMPORTANT NOTE:
	 * Any addition of instance variables need to be included in the toString
	 * (with the excpetion of encodedPubKey and encodedSign)
	 * This is to ensure the integrity of the UserToken for ALL data fields
	 */
	public Token(
		String inIssuer,
		String inSubject,
		ArrayList<String> inGroup,
		String passSecret,
		KeyPair rsa_key
	) {
		issuer=inIssuer;
		subject=inSubject;
		groups=inGroup;
		shownGroups=new ArrayList<String>();
		passwordSecret=passSecret;

		// Crypto Stuff
		encodedPubKey = encodeKey(rsa_key);
		encodedSign = encodeSignature(rsa_key);
	}

	public Token(
		String inIssuer,
		String inSubject,
		ArrayList<String> inGroup,
		ArrayList<String> inShown,
		String passSecret,
		KeyPair rsa_key
	) {
		issuer=inIssuer;
		subject=inSubject;
		groups=inGroup;
		shownGroups=inShown;
		passwordSecret=passSecret;

		//Crypto Stuff
		encodedPubKey = encodeKey(rsa_key);
		encodedSign = encodeSignature(rsa_key);
	}

	/*
	 * For testing UserToken
	 */
	public Token(
		String inIssuer,
		String inSubject,
		ArrayList<String> inGroup,
		ArrayList<String> inShown,
		String passSecret,
		String encPubKey,
		String encSign
	) {
		issuer=inIssuer;
		subject=inSubject;
		groups=inGroup;
		shownGroups=inShown;
		passwordSecret=passSecret;

		encodedPubKey = encPubKey;
		encodedSign = encSign;
	}

	private String encodeKey(KeyPair rsa_key) {
		PublicKey pubKey = rsa_key.getPublic();
		return Base64.getEncoder().encodeToString(pubKey.getEncoded());
	}

	private String encodeSignature(KeyPair rsa_key) {
		Security.addProvider(new BouncyCastleProvider());

		byte[] data = toByte();
		if (data == null) {
			return "";
		}

		try {
			Signature rsa_signature = Signature.getInstance("RSA");
			rsa_signature.initSign(rsa_key.getPrivate(), new SecureRandom());
			rsa_signature.update(data);

			byte[] digitalSignature = rsa_signature.sign();
			return Base64.getEncoder().encodeToString(digitalSignature);
		} catch (Exception e) {
			e.printStackTrace();
			return "";
		}
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
	
	public byte[] getPublicKey() {
		return Base64.getDecoder().decode(encodedPubKey);
	}

	public byte[] getSignature() {
		return Base64.getDecoder().decode(encodedSign);
	}

	public String getPublicKeyEncoded() {
		return encodedPubKey;
	}

	public String getSignatureEncoded() {
		return encodedSign;
	}

	public boolean verify() {
		Security.addProvider(new BouncyCastleProvider());

		byte[] pkData = Base64.getDecoder().decode(encodedPubKey);
		byte[] signature = Base64.getDecoder().decode(encodedSign);
		byte[] expectedData = toByte();

		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(pkData);
            PublicKey publicKey = kf.generatePublic(pkSpec);

            Signature rsa_signature = Signature.getInstance("RSA");

			rsa_signature.initVerify(publicKey);
            rsa_signature.update(expectedData);
			
			return rsa_signature.verify(signature);
		} catch(Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	public byte[] toByte() {
		String strToken = toStringToken();
		byte[] data;

		try {
			data = strToken.getBytes("UTF-8");
			return data;
		} catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public String toStringToken() {
		String str = "";

		// Variables to ignore
		metaVars.add("metaVars");
		metaVars.add("encodedPubKey");
		metaVars.add("encodedSign");

		try {
			Class<?> objClass = this.getClass();

			Field[] fields = objClass.getDeclaredFields();

			for(int i=0; i < fields.length; i++) {
				if (fields[i] == null)
					continue;

				String name = fields[i].getName();
				Object value = fields[i].get(this);
				String encodedVal = "";
				// System.out.println("Name: " + name);
				
				if (!metaVars.contains(name)) {
					// System.out.println("Value: " + value.toString());
					if (value == null) {
						encodedVal = Base64.getEncoder().encodeToString("NULL".getBytes());
						str += name + ": " + encodedVal + "\n";
					} else {
						encodedVal = Base64.getEncoder().encodeToString(value.toString().getBytes());
						str += name + ": " + encodedVal + "\n";
					}
				}else{
					// System.out.println("Value: NULL");
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return str;
	}

	public String toString() {
		String str = "";

		try {
			Class<?> objClass = this.getClass();

			Field[] fields = objClass.getDeclaredFields();

			for(int i=0; i < fields.length; i++) {
				if (fields[i] == null)
					continue;

				String name = fields[i].getName();
				Object value = fields[i].get(this);

				str += name + ": " + value.toString() + "\n";
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return str;
	}

	public static void main(String args[]) {
		String issuer = "issuer";
		String subject = "subject";

		ArrayList<String> groups = new ArrayList<String>();
		groups.add("cat");
		groups.add("dog");
		groups.add("fish");

		ArrayList<String> shownGroups = new ArrayList<String>();
		shownGroups.add("car");
		shownGroups.add("bike");

		KeyPair publicKey;

		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			publicKey = keyPairGenerator.generateKeyPair();
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}

		Token t = new Token(issuer, subject, groups, shownGroups, "PASS", publicKey);

		System.out.println(t);
	}
}