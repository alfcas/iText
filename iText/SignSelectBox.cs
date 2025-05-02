using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace iText
{
    public partial class SignSelectBox : Form
    {
        // sign certificate: Subject dnQualifier=xxxxxxxx SERIALNUMBER=xxxxxxxx CN=xxxxxxxxxxxxxx
        // DNQualifier : denominato IUT (codice univoco del titolare) si trova nei certificati di firma digitale
        //


        private DialogResult p_result = DialogResult.Cancel;
        private int p_index = 0;

        public SignSelectBox(X509Certificate2Collection certificates)
        {
            InitializeComponent();
            int index = 0;

            lvSigns.Columns.Add("Name",140);
            lvSigns.Columns.Add("Subj",180);
            lvSigns.MultiSelect = false;

            // filtra certificati su supporto hardware (token usb)
            RSACryptoServiceProvider csp = null;

            foreach (var item in certificates)
            {
                string serialNumber = item.SerialNumber;
                string subject = item.Subject;
                string issuer = item.Issuer;

                if (/*!item.Subject.Contains("dnQualifier") && */item.HasPrivateKey)
                {
                    try
                    {
                        //*!* casting exception if device not present
                        csp = item.PrivateKey as RSACryptoServiceProvider;
                        if (!csp.CspKeyContainerInfo.HardwareDevice)
                            continue;


                        if (item.NotAfter < DateTime.Now)
                            continue;   //Chain Certificate is Expired

                        var fields = item.Subject.Split(',');
                        Dictionary<string, string> subjectFields = new Dictionary<string, string>();
                        foreach (var field in fields)
                        {
                            int ix = field.IndexOf('=');
                            if (ix < 0)
                            {
                                subjectFields.Add(field, "");
                            }
                            else
                            {
                                subjectFields.Add(field.Substring(0, ix).Trim().ToUpper(), field.Substring(ix + 1).Trim());
                            }
                        }

                        string cnserialNumber = subjectFields.ContainsKey("SERIALNUMBER") ? subjectFields["SERIALNUMBER"] : "";
                        string dnqualifier = subjectFields.ContainsKey("DNQUALIFIER") ? subjectFields["DNQUALIFIER"] : "";
                        string commonName = subjectFields.ContainsKey("CN") ? subjectFields["CN"] : "";
                        string surName = subjectFields.ContainsKey("SN") ? subjectFields["SN"] : "";
                        string givenName = subjectFields.ContainsKey("GN") ? givenName = subjectFields["GN"] : (subjectFields.ContainsKey("G") ? subjectFields["G"] : "");

                        ListViewItem li;
                        if (!string.IsNullOrEmpty(commonName))
                            li = new ListViewItem(new[] { surName + " " + givenName, commonName });
                        else
                            li = new ListViewItem(new[] { surName + " " + givenName, subject });
                        li.Tag = index;
                        lvSigns.Items.Add(li);

                        index++;
                    }
                    catch
                    {
                        ListViewItem li;
                        li = new ListViewItem(new[] { "Unknown certificate", subject  });
                        li.Tag = index;
                        lvSigns.Items.Add(li);
                        //
                        index++;
                    }
                }
            }
        }

        // Modal show dialog 
        new public DialogResult Show()
        {
            base.ShowDialog();
            return p_result;
        }
        new public DialogResult ShowDialog()
        {
            base.ShowDialog();
            return p_result;
        }

        public int Index
        {
            get { return p_index; }
        }


        private void BtnOk_Click(object sender, EventArgs e)
        {
            p_result = DialogResult.OK;
            this.Close();
        }

        private void BtnCancel_Click(object sender, EventArgs e)
        {
            p_result = DialogResult.Cancel;
            this.Close();
        }

        private void LvSigns_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (lvSigns.SelectedItems.Count == 0)
                return;
            var sv = lvSigns.SelectedItems[0];
            p_index = (int)sv.Tag;
        }
    }
}
