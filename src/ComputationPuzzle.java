import java.util.Base64;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.nio.ByteBuffer;

// Crypto Libraries
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;

public class ComputationPuzzle {
    // The number of bits to verify
    private static final int PUZZ_LENGTH = 20;
    private static final int N = 3;

    public static String generatePuzzle() {
        return generatePuzzle(N);
    }

    public static String generatePuzzle(int n) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            // Get the Date to Generate the Nonce
            SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
            Date date = new Date();
            byte[] ftd = formatter.format(date).getBytes("UTF-8");

            byte[] puzz = new byte[PUZZ_LENGTH];
            SecureRandom random = new SecureRandom();
            random.nextBytes(puzz);
            
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(ftd);
            sha.update(puzz);

            byte[] hash = sha.digest();

            byte[] res = new byte[n];
            for (int i=0; i < n; i++) {
                res[i] = hash[hash.length-i-1];
            }

            return Base64.getEncoder().encodeToString(res);
        } catch(Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static boolean compareBytes(byte[] puzzle, byte[] target) {
        for(int i=0; i < puzzle.length; i++) {
            if (puzzle[i] != target[target.length-i-1]) {
                return false;
            }
        }
        return true;
    }

    public static String solvePuzzle(String puzzleEnc) {
        byte[] puzzle = Base64.getDecoder().decode(puzzleEnc);
        long target = 0;
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(0, target);

        byte[] hash;

        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");

            while(target < Long.MAX_VALUE) {
                sha.reset();

                sha.update(buffer.array());
                hash = sha.digest();

                if (compareBytes(puzzle, hash)) {
                    // Target found
                    break;
                }

                target += 1;
                buffer.putLong(0, target);
            }

            return Base64.getEncoder().encodeToString(buffer.array());
        } catch(Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static boolean compareResults(String puzzleEnc, String targetEnc) {
        byte[] puzzle = Base64.getDecoder().decode(puzzleEnc);
        byte[] target = Base64.getDecoder().decode(targetEnc);

        byte[] hash;

        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(target);
            hash = sha.digest();

            return compareBytes(puzzle, hash);
        } catch(Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String args[]) {
        String puzzle = ComputationPuzzle.generatePuzzle();
        String target = ComputationPuzzle.solvePuzzle(puzzle);

        System.out.println(puzzle);
        System.out.println(target);
        System.out.println(ComputationPuzzle.compareResults(puzzle, target));

        long total = 0;

        for(int i=0; i < 10; i++) {
            puzzle = ComputationPuzzle.generatePuzzle();

            long startTime = System.nanoTime();
            ComputationPuzzle.solvePuzzle(puzzle);
            long endTime = System.nanoTime();

            total += (endTime - startTime);
        }

        double seconds = (double)total / 1_000_000_000.0;
        System.out.println("Total time: " + seconds);
        System.out.println("Average Time: " + (seconds/100));
    }
}