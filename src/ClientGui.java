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
	frame.setSize(700,500);

	//connection menu bar
	JMenuBar menu_bar = new JMenuBar();

	JMenu group_menu = new JMenu("Group Server");
	JMenuItem connect_group = new JMenuItem("Connect");
	group_menu.add(connect_group);

	connect_group.addActionListener(new connectG(rcli));

	JMenu file_menu = new JMenu("File Server");
	JMenuItem connect_file = new JMenuItem("Connect");
	file_menu.add(connect_file);

	connect_file.addActionListener(new connectF(rcli));

	JMenu system_menu = new JMenu("System");
	JMenuItem exit_system = new JMenuItem("Exit");
	system_menu.add(exit_system);

	exit_system.addActionListener(new exitSystem(rcli));


	menu_bar.add(group_menu);
	menu_bar.add(file_menu);
	menu_bar.add(system_menu);


	// console output
	JTextArea textArea = new JTextArea(50, 10);
	textArea.setEditable(false);
	PrintStream printStream = new PrintStream(new GuiConsole(textArea));
	System.setOut(printStream);
	System.setErr(printStream);

	// USER ACTIONS
	// get a user token
	JButton get_button = new JButton("GET");
	// create user
	JButton cuser_button = new JButton("Create User");
	// delete user
	JButton duser_button = new JButton("Delete User");
	// create group
	JButton cgroup_button = new JButton("Create Group");
	// delete group
	JButton dgroup_button = new JButton("Delete Group");
	// list members of group
	JButton lmembers_button = new JButton("List Members");
	// add user to a group
	JButton ausertogroup_button = new JButton("Add User to Group");
	// remove a user from a group
	JButton rusertogroup_button = new JButton("Remove User from Group");
	// upload a file
	JButton uploadf_button = new JButton("Upload File");
	// list files
	JButton lfiles_button = new JButton("Add User to Group");
	// download a file
	JButton downloadf_button = new JButton("Download File");
	// delete a file
	JButton deletef_button = new JButton("Delete File");
	// status?
	JButton status_button = new JButton("Status");

	JPanel action_panel = new JPanel();
	action_panel.setLayout(new BoxLayout(action_panel, BoxLayout.Y_AXIS));
	action_panel.add(get_button);
	action_panel.add(cuser_button);
	action_panel.add(duser_button);
	action_panel.add(cgroup_button);
	action_panel.add(dgroup_button);
	action_panel.add(lmembers_button);
	action_panel.add(ausertogroup_button);
	action_panel.add(rusertogroup_button);
	action_panel.add(uploadf_button);
	action_panel.add(lfiles_button);
	action_panel.add(downloadf_button);
	action_panel.add(deletef_button);
	action_panel.add(status_button);

	//layout
	frame.add(menu_bar, BorderLayout.NORTH);
	frame.add(textArea, BorderLayout.CENTER);
	frame.add(action_panel, BorderLayout.WEST);


	frame.setVisible(true);
	}

	static class connectG implements ActionListener{
	RunClient rcli;
	public connectG(RunClient _rcli){
			rcli = _rcli;
	}
	public void actionPerformed(ActionEvent ev) {
				String ip = JOptionPane.showInputDialog("Enter IP");
				String port = JOptionPane.showInputDialog("Enter Port");

				String temp = "connect group " + ip + " " + port;
				StringTokenizer cmd = new StringTokenizer(temp);

				rcli.mapCommand(cmd);
			}
	}

	static class connectF implements ActionListener{
		RunClient rcli;
		public connectF(RunClient _rcli){
			rcli = _rcli;
		}
		public void actionPerformed(ActionEvent ev) {
			String ip = JOptionPane.showInputDialog("Enter IP");
			String port = JOptionPane.showInputDialog("Enter Port");

			String temp = "connect file " +ip + " " + port;
			StringTokenizer cmd = new StringTokenizer(temp);

			rcli.mapCommand(cmd);
		}
	}

	static class exitSystem implements ActionListener{
		RunClient rcli;
		public exitSystem(RunClient _rcli){
			rcli = _rcli;
		}
		public void actionPerformed(ActionEvent ev) {
			StringTokenizer cmd = new StringTokenizer("exit");
			rcli.mapCommand(cmd);
			System.exit(0);
		}
	}
}
