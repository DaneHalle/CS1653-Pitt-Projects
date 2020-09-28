import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.PrintStream;
import java.util.StringTokenizer;

public class ClientGui{
    public static void main(String args[]){

      RunClient rcli = new RunClient();

      StringTokenizer cmd;


      JFrame frame = new JFrame("Client");
      frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
      frame.setSize(700,800);

      //connection menu bar
      JMenuBar menu_bar = new JMenuBar();

      JMenu group_menu = new JMenu("Group Server");
      JMenuItem connect_group = new JMenuItem("Connect");
      group_menu.add(connect_group);

      connect_group.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent ev) {
                  String ip = JOptionPane.showInputDialog("Enter IP");
                  String port = JOptionPane.showInputDialog("Enter Port");

                  String temp = "connect group " + ip + " " + port;
                  StringTokenizer cmd = new StringTokenizer(temp);

                  rcli.mapCommand(cmd);
              }
      });

      JMenu file_menu = new JMenu("File Server");
      JMenuItem connect_file = new JMenuItem("Connect");
      file_menu.add(connect_file);

      connect_file.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent ev) {
                  String ip = JOptionPane.showInputDialog("Enter IP");
                  String port = JOptionPane.showInputDialog("Enter Port");

                  String temp = "connect file " +ip + " " + port;
                  StringTokenizer cmd = new StringTokenizer(temp);

                  rcli.mapCommand(cmd);
              }
      });

      JMenu system_menu = new JMenu("System");
      JMenuItem exit_system = new JMenuItem("Exit");
      system_menu.add(exit_system);

      exit_system.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent ev) {
                  StringTokenizer cmd = new StringTokenizer("exit");
                  rcli.mapCommand(cmd);
                  System.exit(0);
              }
      });


      menu_bar.add(group_menu);
      menu_bar.add(file_menu);
      menu_bar.add(system_menu);

      JTextArea textArea = new JTextArea(50, 10);
      textArea.setEditable(false);
      PrintStream printStream = new PrintStream(new GuiConsole(textArea));
      System.setOut(printStream);
      System.setErr(printStream);

      //layout
      frame.add(menu_bar, BorderLayout.NORTH);
      frame.add(textArea, BorderLayout.CENTER);


      frame.setVisible(true);
    }
}