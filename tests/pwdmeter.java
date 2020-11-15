import java.lang.Math;
public class pwdmeter {
	public static void main(String args[]) {
		System.out.println(args[0]);
		// Simultaneous variable declaration and value assignment aren't supported in IE apparently
		// so I'm forced to assign the same value individually per var to support a crappy browser *sigh* 
		double nScore=0, nLength=0, nAlphaUC=0, nAlphaLC=0, nNumber=0, nSymbol=0, nMidChar=0, nRequirements=0, nAlphasOnly=0, nNumbersOnly=0, nUnqChar=0, nRepChar=0, nConsecAlphaUC=0, nConsecAlphaLC=0, nConsecNumber=0, nConsecSymbol=0, nConsecCharType=0, nSeqAlpha=0, nSeqNumber=0, nSeqSymbol=0, nRepInc=0, nSeqChar=0, nReqChar=0, nMultConsecCharType=0;
		double nMultRepChar=1, nMultConsecSymbol=1;
		double nMultMidChar=2, nMultRequirements=2, nMultConsecAlphaUC=2, nMultConsecAlphaLC=2, nMultConsecNumber=2;
		double nReqCharType=3, nMultAlphaUC=3, nMultAlphaLC=3, nMultSeqAlpha=3, nMultSeqNumber=3, nMultSeqSymbol=3;
		double nMultLength=4, nMultNumber=4;
		double nMultSymbol=6;
		String nTmpAlphaUC="", nTmpAlphaLC="", nTmpNumber="", nTmpSymbol="";
		String sAlphaUC="0", sAlphaLC="0", sNumber="0", sSymbol="0", sMidChar="0", sRequirements="0", sAlphasOnly="0", sNumbersOnly="0", sRepChar="0", sConsecAlphaUC="0", sConsecAlphaLC="0", sConsecNumber="0", sSeqAlpha="0", sSeqNumber="0", sSeqSymbol="0";
		String sAlphas = "abcdefghijklmnopqrstuvwxyz";
		String sNumerics = "01234567890";
		String sSymbols = ")!@#$%^&*()";
		String sComplexity = "Too Short";
		String sStandards = "Below";
		double nMinPwdLen = 8;
		double nd = 0;
		String pwd = args[0];

		nScore = pwd.length() * nMultLength;
		nLength = pwd.length();
		String[] arrPwd = pwd.split("");
		int arrPwdLen = arrPwd.length;
		
		/* Loop through password to check for Symbol, Numeric, Lowercase and Uppercase pattern matches */
		for (int a=0; a < arrPwdLen; a++) {
			if (sAlphas.toUpperCase().contains(arrPwd[a])) {
				if (nTmpAlphaUC != "") { if ((nTmpAlphaUC + 1) == ""+a) { nConsecAlphaUC++; nConsecCharType++; } }
				nTmpAlphaUC = ""+a;
				nAlphaUC++;
			}
			else if (sAlphas.contains(arrPwd[a])) { 
				if (nTmpAlphaLC != "") { if ((nTmpAlphaLC + 1) == ""+a) { nConsecAlphaLC++; nConsecCharType++; } }
				nTmpAlphaLC = ""+a;
				nAlphaLC++;
			}
			else if (sNumerics.contains(arrPwd[a])) { 
				if (a > 0 && a < (arrPwdLen - 1)) { nMidChar++; }
				if (nTmpNumber != "") { if ((nTmpNumber + 1) == ""+a) { nConsecNumber++; nConsecCharType++; } }
				nTmpNumber = ""+a;
				nNumber++;
			}
			else if (sSymbols.contains(arrPwd[a])) { 
				if (a > 0 && a < (arrPwdLen - 1)) { nMidChar++; }
				if (nTmpSymbol != "") { if ((nTmpSymbol + 1) == ""+a) { nConsecSymbol++; nConsecCharType++; } }
				nTmpSymbol = ""+a;
				nSymbol++;
			}
			/* Internal loop through password to check for repeat characters */
			boolean bCharExists = false;
			for (int b=0; b < arrPwdLen; b++) {
				if (arrPwd[a] == arrPwd[b] && a != b) { /* repeat character exists */
					bCharExists = true;
					nRepInc += Math.abs(arrPwdLen/(b-a));
				}
			}
			if (bCharExists) { 
				nRepChar++; 
				nUnqChar = arrPwdLen-nRepChar;
				nRepInc = (nUnqChar!=0) ? Math.ceil(nRepInc/nUnqChar) : Math.ceil(nRepInc); 
			}
		}
		
		/* Check for sequential alpha string patterns (forward and reverse) */
		for (int s=0; s < 23; s++) {
			String sFwd = sAlphas.substring(s,s+3);
			byte[] strAsByteArray = sFwd.getBytes();
			byte[] result = new byte[strAsByteArray.length];
			for (int i = 0; i < strAsByteArray.length; i++)
            	result[i] = strAsByteArray[strAsByteArray.length - i - 1];

			String sRev = new String(result);
			if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) { nSeqAlpha++; nSeqChar++;}
		}
		
		/* Check for sequential numeric string patterns (forward and reverse) */
		for (int s=0; s < 8; s++) {
			String sFwd = sNumerics.substring(s,s+3);
			byte[] strAsByteArray = sFwd.getBytes();
			byte[] result = new byte[strAsByteArray.length];
			for (int i = 0; i < strAsByteArray.length; i++)
            	result[i] = strAsByteArray[strAsByteArray.length - i - 1];

			String sRev = new String(result);
			if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) { nSeqNumber++; nSeqChar++;}
		}
		
		/* Check for sequential symbol string patterns (forward and reverse) */
		for (int s=0; s < 8; s++) {
			String sFwd = sSymbols.substring(s,s+3);
			byte[] strAsByteArray = sFwd.getBytes();
			byte[] result = new byte[strAsByteArray.length];
			for (int i = 0; i < strAsByteArray.length; i++)
            	result[i] = strAsByteArray[strAsByteArray.length - i - 1];

			String sRev = new String(result);
			if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) { nSeqSymbol++; nSeqChar++;}
		}
		
	/* Modify overall score value based on usage vs requirements */

		/* General point assignment */
		// $("nLengthBonus").innerHTML = "+ " + nScore; 
		if (nAlphaUC > 0 && nAlphaUC < nLength) {	
			nScore = (nScore + ((nLength - nAlphaUC) * 2));
			sAlphaUC = "+ " + ((nLength - nAlphaUC) * 2); 
		}
		if (nAlphaLC > 0 && nAlphaLC < nLength) {	
			nScore = (nScore + ((nLength - nAlphaLC) * 2)); 
			sAlphaLC = "+ " + ((nLength - nAlphaLC) * 2);
		}
		if (nNumber > 0 && nNumber < nLength) {	
			nScore = (nScore + (nNumber * nMultNumber));
			sNumber = "+ " + (nNumber * nMultNumber);
		}
		if (nSymbol > 0) {	
			nScore = (nScore + (nSymbol * nMultSymbol));
			sSymbol = "+ " + (nSymbol * nMultSymbol);
		}
		if (nMidChar > 0) {	
			nScore = (nScore + (nMidChar * nMultMidChar));
			sMidChar = "+ " + (nMidChar * nMultMidChar);
		}
		
		/* Point deductions for poor practices */
		if ((nAlphaLC > 0 || nAlphaUC > 0) && nSymbol == 0 && nNumber == 0) {  // Only Letters
			nScore = (nScore - nLength);
			nAlphasOnly = nLength;
			sAlphasOnly = "- " + nLength;
		}
		if (nAlphaLC == 0 && nAlphaUC == 0 && nSymbol == 0 && nNumber > 0) {  // Only Numbers
			nScore = (nScore - nLength); 
			nNumbersOnly = nLength;
			sNumbersOnly = "- " + nLength;
		}
		if (nRepChar > 0) {  // Same character exists more than once
			nScore = (nScore - nRepInc);
			sRepChar = "- " + nRepInc;
		}
		if (nConsecAlphaUC > 0) {  // Consecutive Uppercase Letters exist
			nScore = (nScore - (nConsecAlphaUC * nMultConsecAlphaUC)); 
			sConsecAlphaUC = "- " + (nConsecAlphaUC * nMultConsecAlphaUC);
		}
		if (nConsecAlphaLC > 0) {  // Consecutive Lowercase Letters exist
			nScore = (nScore - (nConsecAlphaLC * nMultConsecAlphaLC)); 
			sConsecAlphaLC = "- " + (nConsecAlphaLC * nMultConsecAlphaLC);
		}
		if (nConsecNumber > 0) {  // Consecutive Numbers exist
			nScore = (nScore - (nConsecNumber * nMultConsecNumber));  
			sConsecNumber = "- " + (nConsecNumber * nMultConsecNumber);
		}
		if (nSeqAlpha > 0) {  // Sequential alpha strings exist (3 characters or more)
			nScore = (nScore - (nSeqAlpha * nMultSeqAlpha)); 
			sSeqAlpha = "- " + (nSeqAlpha * nMultSeqAlpha);
		}
		if (nSeqNumber > 0) {  // Sequential numeric strings exist (3 characters or more)
			nScore = (nScore - (nSeqNumber * nMultSeqNumber)); 
			sSeqNumber = "- " + (nSeqNumber * nMultSeqNumber);
		}
		if (nSeqSymbol > 0) {  // Sequential symbol strings exist (3 characters or more)
			nScore = (nScore - (nSeqSymbol * nMultSeqSymbol)); 
			sSeqSymbol = "- " + (nSeqSymbol * nMultSeqSymbol);
		}
		
		/* Determine complexity based on overall score */
		if (nScore > 100) { nScore = 100; } else if (nScore < 0) { nScore = 0; }
		if (nScore >= 0 && nScore < 20) { sComplexity = "Very Weak"; }
		else if (nScore >= 20 && nScore < 40) { sComplexity = "Weak"; }
		else if (nScore >= 40 && nScore < 60) { sComplexity = "Good"; }
		else if (nScore >= 60 && nScore < 80) { sComplexity = "Strong"; }
		else if (nScore >= 80 && nScore <= 100) { sComplexity = "Very Strong"; }
		
		System.out.println(nScore);
		System.out.println(sComplexity);
	}
}