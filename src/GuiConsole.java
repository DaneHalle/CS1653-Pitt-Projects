import java.io.OutputStream;
import java.io.IOException;
import java.io.PrintStream;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class GuiConsole extends OutputStream {
    private JTextArea textArea;

    public GuiConsole(JTextArea textArea) {
        this.textArea = textArea;
    }

    @Override
    public void write(int b) throws IOException {
        // redirects data to the text area
        textArea.append(String.valueOf((char)b));
        // scrolls the text area to the end of data
        textArea.setCaretPosition(textArea.getDocument().getLength());
    }
}
