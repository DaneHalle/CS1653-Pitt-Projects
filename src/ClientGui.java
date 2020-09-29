import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.PrintStream;
import java.util.StringTokenizer;
import java.io.File;

public class ClientGui{
	public static void main(String args[]){

		RunClient rcli = new RunClient();

		JFrame frame = new JFrame("Client");
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setSize(700,500);

		//connection menu bar
		JMenuBar menu_bar = new JMenuBar();

		JMenu group_menu = new JMenu("Group Server");
		JMenuItem connect_group = new JMenuItem("Connect");
		group_menu.add(connect_group);

		String[] connect_prompts = {"Enter IP", "Enter port"};
		connect_group.addActionListener(new arbAction(rcli, "connect group", connect_prompts));

		JMenu file_menu = new JMenu("File Server");
		JMenuItem connect_file = new JMenuItem("Connect");
		file_menu.add(connect_file);

		connect_file.addActionListener(new arbAction(rcli, "connect file", connect_prompts));

		JMenu system_menu = new JMenu("System");
		JMenuItem exit_system = new JMenuItem("Exit");
		system_menu.add(exit_system);

		exit_system.addActionListener(new exitSystem(rcli));

		menu_bar.add(group_menu);
		menu_bar.add(file_menu);
		menu_bar.add(system_menu);

		// console output
		JTextArea console = new JTextArea();
		console.setEditable(false);
		PrintStream printStream = new PrintStream(new GuiConsole(console));
		System.setOut(printStream);
		System.setErr(printStream);

		JScrollPane consoleShell = new JScrollPane(console);

		// USER ACTIONS
		// get a user token
		JButton get_button = new JButton("GET");
		String[] get_prompts = {"Enter username"};
		get_button.addActionListener(new arbAction(rcli, "get", get_prompts));

		// create user
		JButton cuser_button = new JButton("Create User");
		String[] cuser_prompts = {"Enter new username"};
		cuser_button.addActionListener(new arbAction(rcli, "cuser", cuser_prompts));

		// delete user
		JButton duser_button = new JButton("Delete User");
		String[] duser_prompts = {"Enter username to be deleted"};
		duser_button.addActionListener(new arbAction(rcli, "duser", duser_prompts));

		// create group
		JButton cgroup_button = new JButton("Create Group");
		String[] cgroup_prompts = {"Enter new group name"};
		cgroup_button.addActionListener(new arbAction(rcli, "cgroup", cgroup_prompts));

		// delete group
		JButton dgroup_button = new JButton("Delete Group");
		String[] dgroup_prompts = {"Enter group to be deleted"};
		dgroup_button.addActionListener(new arbAction(rcli, "dgroup", dgroup_prompts));

		// list members of group
		JButton lmembers_button = new JButton("List Members");
		String[] lmembers_prompts = {"Enter group name"};
		lmembers_button.addActionListener(new arbAction(rcli, "lmembers", lmembers_prompts));

		// add user to a group
		JButton ausertogroup_button = new JButton("Add User to Group");
		String[] ausertogroup_prompts = {"Enter username", "Enter group name"};
		ausertogroup_button.addActionListener(new arbAction(rcli, "ausertogroup", ausertogroup_prompts));

		// remove a user from a group
		JButton ruserfromgroup_button = new JButton("Remove User from Group");
		String[] ruserfromgroup_prompts = {"Enter username", "Enter group name"};
		ruserfromgroup_button.addActionListener(new arbAction(rcli, "ruserfromgroup", ruserfromgroup_prompts));

		// upload a file
		JButton uploadf_button = new JButton("Upload File");
		String[] uploadf_prompts = {"Enter src filename", "Enter dest filename", "Enter group name"};
		// uploadf_button.addActionListener(new arbAction(rcli, "uploadf", uploadf_prompts));
		uploadf_button.addActionListener(new fileUpload(rcli, frame));



		// list files
		JButton lfiles_button = new JButton("List Files");
		String[] lfiles_prompts = {};
		lfiles_button.addActionListener(new arbAction(rcli, "lfiles", lfiles_prompts));

		// download a file
		JButton downloadf_button = new JButton("Download File");
		String[] downloadf_prompts = {"Enter src filename", "Enter dest filename"};
		downloadf_button.addActionListener(new arbAction(rcli, "downloadf", downloadf_prompts));

		// delete a file
		JButton deletef_button = new JButton("Delete File");
		String[] deletef_prompts = {"Enter file to be deleted"};
		deletef_button.addActionListener(new arbAction(rcli, "deletef", deletef_prompts));

		// status?
		JButton status_button = new JButton("Status");
		String[] status_prompts = {};
		status_button.addActionListener(new arbAction(rcli, "status", status_prompts));

		JPanel action_panel = new JPanel(new GridLayout(13,1));
		// action_panel.setLayout(new BoxLayout(action_panel, BoxLayout.Y_AXIS));
		action_panel.add(get_button);
		action_panel.add(cuser_button);
		action_panel.add(duser_button);
		action_panel.add(cgroup_button);
		action_panel.add(dgroup_button);
		action_panel.add(lmembers_button);
		action_panel.add(ausertogroup_button);
		action_panel.add(ruserfromgroup_button);
		action_panel.add(uploadf_button);
		action_panel.add(lfiles_button);
		action_panel.add(downloadf_button);
		action_panel.add(deletef_button);
		action_panel.add(status_button);

		//layout
		frame.add(menu_bar, BorderLayout.NORTH);
		frame.add(consoleShell, BorderLayout.CENTER);
		frame.add(action_panel, BorderLayout.WEST);


		frame.setVisible(true);
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

	static class arbAction implements ActionListener{
		RunClient rcli;
		String action;
		String[] prompts;
		public arbAction(RunClient _rcli, String _action, String[] _prompts){
			rcli = _rcli;
			action = _action;
			prompts = _prompts;
		}
		public void actionPerformed(ActionEvent ev) {
			String actionOptions = "";
			boolean flag = true;
			for(int i = 0; i < prompts.length; i++){
				String temp = JOptionPane.showInputDialog(prompts[i]);
				if(temp != null) actionOptions = actionOptions + " " + temp;
				else flag = false;
			}
			System.out.println("Action: " + action + " " + actionOptions);
			StringTokenizer cmd = new StringTokenizer(action + " " + actionOptions);

			if(flag) rcli.mapCommand(cmd);
		}
	}


	static class fileUpload implements ActionListener{
		RunClient rcli;
		JFrame parentFrame;
		File file;
		public fileUpload(RunClient _rcli, JFrame _parentFrame){
			rcli = _rcli;
			parentFrame = _parentFrame;
		}
		public void actionPerformed(ActionEvent ev) {
			final JFileChooser fc = new JFileChooser();
			int val = fc.showDialog(parentFrame, "Choose file to upload");
			if(val == JFileChooser.CANCEL_OPTION){
				System.out.println("Upload cancelled by client");
			}else if(val == JFileChooser.APPROVE_OPTION){
				file = fc.getSelectedFile();
				System.out.println("Chose file (" + file.getName() + ") to upload");
				System.out.println("Path: " + file.getPath());
			}else{
				System.out.println("Error choosing file");
			}
		}
	}
}
