public class sim {
	public static void main(String[] args) {
		String pass = "Password";
		String leet = "P@55w0rd";
		double res = similarity(pass, leet);
		double res1 = similarity
		System.out.println(res);
	}

	// Example implementation of the Levenshtein Edit Distance
	// See http://rosettacode.org/wiki/Levenshtein_distance#Java
	public static double similarity(String ref, String toCompare) {
		String longer = ref.toLowerCase();
		String shorter = toCompare.toLowerCase();
		if (ref.length() < toCompare.length()) { // longer should always have greater length
			longer = toCompare; shorter = ref;
		}
		if (longer.length() == 0) { return 1.0; /* both strings are zero length */ }

		int[] costs = new int[shorter.length() + 1];
		for (int i = 0; i <= longer.length(); i++) {
			int last = i;
			for (int j = 0; j <= shorter.length(); j++) {
				if (i == 0) {
					costs[j] = j;
				} else {
					if (j > 0) {
						int val = costs[j - 1];
						if (longer.charAt(i - 1) != shorter.charAt(j - 1)) {
							val = Math.min(last, val);
							val = Math.min(costs[j], val) + 1;
						}
						costs[j - 1] = last;
						last = val;
					}
				}
			}
			if (i > 0) {
				costs[shorter.length()] = last;
			}
		}

		return (longer.length() - costs[shorter.length()]) / (double) longer.length();
	}

}

