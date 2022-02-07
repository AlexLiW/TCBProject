package main;

import java.awt.EventQueue;

import javax.swing.JFrame;
import java.awt.FlowLayout;
import java.awt.FontMetrics;

import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import main.DoAuthGenerator;

public class AuthGenerator {

	private JFrame frame;
	private JTextField TxT_code,TxT_idno,TxT_timestamp,TxT_ASE_KEY,lb_Auth;
	private JButton btnNowtime;
	private JTextField lb_sha256hex;
	private JButton btnGenchkCode;
	private JTextField TxT_16KeyRandom;
	private JButton btn16Key;
	private JButton btnGenerator;
	private JButton btndecrypt;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					AuthGenerator window = new AuthGenerator();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public AuthGenerator() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 800, 542);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);
		
		JLabel lb_16key = new JLabel("16key : ");
		lb_16key.setBounds(15, 13, 100, 40);
		frame.getContentPane().add(lb_16key);
		
		JLabel lb_code = new JLabel("code : ");
		lb_code.setBounds(15, 73, 100, 40);
		frame.getContentPane().add(lb_code);
		
		JLabel lb_idno = new JLabel("idno : ");
		lb_idno.setBounds(15, 122, 100, 40);
		frame.getContentPane().add(lb_idno);
		
		JLabel lb_timestamp = new JLabel("timestamp : ");
		lb_timestamp.setBounds(15, 175, 100, 40);
		frame.getContentPane().add(lb_timestamp);
		
		JLabel lb_AES_KEY = new JLabel("AES_KEY : ");
		lb_AES_KEY.setBounds(15, 298, 100, 23);
		frame.getContentPane().add(lb_AES_KEY);
		
		TxT_code = new JTextField();
		TxT_code.setBounds(150, 74, 300, 40);
		frame.getContentPane().add(TxT_code);
		TxT_code.setColumns(10);
		
		TxT_idno = new JTextField();
		TxT_idno.setBounds(150, 123, 300, 40);
		frame.getContentPane().add(TxT_idno);
		TxT_idno.setColumns(10);
		
		TxT_timestamp = new JTextField();
		TxT_timestamp.setBounds(150, 176, 300, 40);
		frame.getContentPane().add(TxT_timestamp);
		TxT_timestamp.setColumns(10);
		
		TxT_ASE_KEY = new JTextField();
		TxT_ASE_KEY.setBounds(150, 290, 300, 40);
		frame.getContentPane().add(TxT_ASE_KEY);
		TxT_ASE_KEY.setColumns(10);
		
		lb_Auth = new JTextField();
		lb_Auth.setBounds(15, 378, 748, 100);
		frame.getContentPane().add(lb_Auth);
		lb_Auth.setColumns(10);
		
		//JButton btnGenerator = new JButton("Generator");
		btnGenerator = new JButton("Generator");
		btnGenerator.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				String auth = new DoAuthGenerator().getAuth(TxT_idno.getText(),TxT_code.getText(),TxT_timestamp.getText(),TxT_ASE_KEY.getText());
				lb_Auth.setText(auth);
			}
		});
		btnGenerator.setBounds(102, 344, 111, 31);
		frame.getContentPane().add(btnGenerator);
		
		btnNowtime = new JButton("nowTime");
		btnNowtime.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				TxT_timestamp.setText(new DoAuthGenerator().getNowTimeStamp());
			}
		});
		btnNowtime.setBounds(464, 180, 111, 31);
		frame.getContentPane().add(btnNowtime);
		
		JLabel lb_Sha256Hex_KEY_1 = new JLabel("checkCode : ");
		lb_Sha256Hex_KEY_1.setBounds(15, 242, 100, 23);
		frame.getContentPane().add(lb_Sha256Hex_KEY_1);
		
		JLabel lb_AESResult_KEY_1_1 = new JLabel("AES Result : ");
		lb_AESResult_KEY_1_1.setBounds(15, 348, 100, 23);
		frame.getContentPane().add(lb_AESResult_KEY_1_1);
		
		lb_sha256hex = new JTextField();
		lb_sha256hex.setBounds(150, 237, 300, 40);
		frame.getContentPane().add(lb_sha256hex);
		
		btnGenchkCode = new JButton("GenchkCode");
		btnGenchkCode.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String chkCode = new DoAuthGenerator().getCheckCode(TxT_idno.getText(),TxT_code.getText(),TxT_timestamp.getText(),TxT_ASE_KEY.getText());
				lb_sha256hex.setText(chkCode);
			}
		});
		btnGenchkCode.setBounds(464, 238, 111, 31);
		frame.getContentPane().add(btnGenchkCode);
		
		TxT_16KeyRandom = new JTextField();
		TxT_16KeyRandom.setColumns(10);
		TxT_16KeyRandom.setBounds(150, 21, 300, 40);
		frame.getContentPane().add(TxT_16KeyRandom);
		
		JButton btnGenchkCode_1 = new JButton("GenerateAES");
		btnGenchkCode_1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				String AESKey = new DoAuthGenerator().getAESkey(TxT_idno.getText(),TxT_16KeyRandom.getText());
				TxT_ASE_KEY.setText(AESKey);
			}
		});
		btnGenchkCode_1.setBounds(464, 296, 111, 31);
		frame.getContentPane().add(btnGenchkCode_1);
		
		btn16Key = new JButton("Random16");
		btn16Key.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				TxT_16KeyRandom.setText(new DoAuthGenerator().getRandom16Key());
			}
		});
		btn16Key.setBounds(464, 25, 111, 31);
		frame.getContentPane().add(btn16Key);
		
		btndecrypt = new JButton("Decrypt");
		btndecrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				TxT_16KeyRandom.setText(new DoAuthGenerator().AESdecrypt(TxT_ASE_KEY.getText(),lb_Auth.getText()));
			}
		});
		btndecrypt.setBounds(652, 344, 111, 31);
		frame.getContentPane().add(btndecrypt);
	}
}
