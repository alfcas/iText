/*
 * This class is part of the white paper entitled
 * "Digital Signatures for PDF documents"
 * written by Bruno Lowagie
 * 
 * For more info, go to: http://itextpdf.com/learn
 */

/*
 * using
 * iTextSharp versione 5.5.12
*/

using System;
using System.Windows.Forms;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Security;
using iTextSharp.text;
using iTextSharp.text.log;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
//
using Org.BouncyCastle.Pkcs;


namespace iText
{

    public class PdfDigitalSign
    {
        // sign rectangle struct

        public struct SealRect
        {
            // pdf page coordinates 

            public int LowerLeftX;
            public int LowerLeftY;
            public int UpperRightX;
            public int UpperRightY;
        }



        public enum SignRenderingMode
        {
            Graphic=0, GraphicAndDescription=1, Description=2, NameAndDescription=3
        }

        private SignRenderingMode p_signRenderingMode;


        public enum SignOnPage
        {
            First=0, Last=1, Every=2
        }
        private SignOnPage p_signOnPage=SignOnPage.Last;

        private iTextSharp.text.Rectangle p_signStampRectangle;     // sign stamp
        private iTextSharp.text.Image p_signImage = null;
        private iTextSharp.text.Rectangle p_signNoteRectangle;      // sign note (for other pages)
        private iTextSharp.text.Image p_noteImage = null;

        private string p_signedBy="";
        private string p_reason="";
		private string p_location="";

		private string p_certificateFile="";
        private string p_certificatePassword="";
        private string p_certificateIdentifier="";

        private bool p_validOnly = true;
		
        /// <summary>
        /// Constructor
        /// </summary>
        public PdfDigitalSign()
        {
            p_signRenderingMode = SignRenderingMode.Graphic;


            // pdf page coordinates type:
            //
            //         y|
            //          | pdf page
            //          |                          low     high
            //      0,0 +----------x              x   y    x   y

            // default sign stamp rectangles
            p_signNoteRectangle = new Rectangle( 20, 20, 140, 180);
            p_signStampRectangle = new Rectangle(400, 20, 510, 65);
        }

		#region Properties
        public string SignedBy
        {
            get {
                return p_signedBy;
            }
            set {
                p_signedBy = value;
            }
        }
        //
        public string Reason
        {
			get {
				return p_reason;
			}
			set {
				p_reason = value;
			}
		}
        //
		public string Location
        {
			get {
				return p_location;
			}
			set {
				p_location = value;
			}
		}

        public SignOnPage SignOnPageKind
        {
            get {
                return p_signOnPage;
            }
            set {
                p_signOnPage = value;
            }
        }
        public SignRenderingMode RenderingMode
        {
            get { return p_signRenderingMode; }
            set { p_signRenderingMode = value; }
        }

        public SealRect SignRectangle
        {
            set {
                p_signStampRectangle = new Rectangle(value.LowerLeftX, value.LowerLeftY, value.UpperRightX, value.UpperRightY);
            }
        }
        public SealRect AnnotationRectangle
        {
            set
            {
                p_signNoteRectangle = new Rectangle(value.LowerLeftX, value.LowerLeftY, value.UpperRightX, value.UpperRightY);
            }
        }

        public string NoteImage {
        	set {
        		try {
	        		p_noteImage = iTextSharp.text.Image.GetInstance( value );
                }
                catch {
        			p_noteImage= null;
        		}
        	}
        }
        public FileStream NoteImageStream
        {
            set
            {
                try
                {
                    p_noteImage = iTextSharp.text.Image.GetInstance(value);
                }
                catch
                {
                    p_noteImage = null;
                }
            }
        }
        public string SignImage {
        	set {
        		try {
	        		p_signImage = iTextSharp.text.Image.GetInstance( value );
        		}
        		catch {
        			p_signImage= null;
        		}
        	}
        }
        public FileStream SignImageStream
        {
            set
            {
                try
                {
                    p_signImage = iTextSharp.text.Image.GetInstance(value);
                }
                catch
                {
                    p_signImage = null;
                }
            }
        }


        public bool FindValidCertificateOnly
        {
            get { return p_validOnly; }
            set { p_validOnly = value; }
        }
        public string CertificateIdentifier
        {
            get { return p_certificateIdentifier; }
            set { p_certificateIdentifier = value; }
        }


        public string CertificateFile
        {
            set { p_certificateFile = value; }
        }
        public string CertificatePassword
        {
            set { p_certificatePassword = value; }
        }

		#endregion

        public bool SelectCertificate(out X509Certificate2 cert)
        {
            // certificati personali
            X509Store x509Store = new X509Store("My");
            x509Store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certificates = x509Store.Certificates;
            SignSelectBox dlg = new SignSelectBox(certificates);
            if (dlg.ShowDialog() == DialogResult.OK)
            {
                cert = certificates[dlg.Index];
                return true;
            }
            else
            {
                cert = null;
                return false;
            }
        }
        public void ShowCertificates()
        {
            // certificati personali
            X509Store x509Store = new X509Store("My");
            x509Store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certificates = x509Store.Certificates;
            SignSelectBox dlg = new SignSelectBox(certificates);
            if (dlg.ShowDialog() == DialogResult.OK)
            {
                var cert = certificates[dlg.Index];
                return;
            }
            else
            {
                return;
            }
        }


        private bool Sign(string src, string dest,
                         ICollection<X509Certificate> chain, X509Certificate2 pk,
                         String digestAlgorithm, CryptoStandard subfilter,
                         String reason, String location,
                         ICollection<ICrlClient> crlList,
                         IOcspClient ocspClient,
                         ITSAClient tsaClient,
                         int estimatedSize)
        {
            // Creating the reader and the stamper
            PdfReader reader = null;
            FileStream writer = null;
            PdfStamper stamper = null;

            try
            {
                reader = new PdfReader(src);
                writer = new FileStream(dest, FileMode.Create);
                stamper = PdfStamper.CreateSignature(reader, writer, '\0');
                //
				int firstPage = 1;  // no ZERO
                int lastPage = reader.NumberOfPages;
                //
                // indicazione di firma digitale su tutte la pagine (come PdfAnnotation)
                // la firma effettiva la mettiamo all'ultima pagina, quindi la si esclude
                // dalle pagine da segnare (i < lastPage)
                //
                if (p_signOnPage == SignOnPage.Every && p_noteImage != null)
                {
                    p_noteImage.SetAbsolutePosition(0, 0);
                    for (int i = firstPage; i < lastPage; i++)
                    {
                        //l'ultima pagina salta perchè ha la firma
                        PdfAnnotation stp = PdfAnnotation.CreateStamp(stamper.Writer, p_signNoteRectangle, "", "STP" + i);
                        PdfAppearance tp = PdfAppearance.CreateAppearance(stamper.Writer, p_noteImage.PlainHeight, p_noteImage.PlainWidth);
                        p_noteImage.ScaleToFit(p_noteImage.PlainHeight, p_noteImage.PlainWidth);
                        tp.AddImage(p_noteImage);
                        stp.SetAppearance(PdfAnnotation.APPEARANCE_NORMAL, tp);
                        stamper.AddAnnotation(stp, i);
                    }
                }

                //
                // Create sign appearance
                //
                PdfSignatureAppearance appearance = stamper.SignatureAppearance;
                //
                appearance.Reason = reason;
                appearance.Location = location;
				// Custom text and custom font
                if (p_signedBy != "")
                {
    				appearance.Layer2Text = "This document was signed by " + p_signedBy;
    				appearance.Layer2Font = new Font(Font.FontFamily.TIMES_ROMAN);
//				    // Custom text, custom font, and right-to-left writing
//				    appearance.Layer2Text = "\u0644\u0648\u0631\u0627\u0646\u0633 \u0627\u0644\u0639\u0631\u0628";
//				    appearance.RunDirection = PdfWriter.RUN_DIRECTION_RTL;
//				    appearance.Layer2Font = new Font(BaseFont.CreateFont("C:/windows/fonts/arialuni.ttf", BaseFont.IDENTITY_H, BaseFont.EMBEDDED), 12);
                }

                switch (p_signRenderingMode)
                {
                    case SignRenderingMode.Graphic:
                        appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.GRAPHIC;
                        appearance.SignatureGraphic = p_noteImage; //iTextSharp.text.Image.GetInstance(@"resources\timbro.png");
                        break;
                    case SignRenderingMode.GraphicAndDescription:
                        appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION;
                        appearance.SignatureGraphic = p_noteImage; //iTextSharp.text.Image.GetInstance(@"resources\timbro.png");
                        break;
                    case SignRenderingMode.Description:
                        appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
                        appearance.Image = p_signImage; //iTextSharp.text.Image.GetInstance(@"resources\sfondo.png");
                        break;
                    case SignRenderingMode.NameAndDescription:
                        appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.NAME_AND_DESCRIPTION;
                        appearance.Image = p_signImage; //iTextSharp.text.Image.GetInstance(@"resources\sfondo.png");
                        break;
                }
                if (p_signOnPage == SignOnPage.First) {
                    appearance.SetVisibleSignature(p_signStampRectangle, firstPage, "sig");
                }
                else {
                    appearance.SetVisibleSignature(p_signStampRectangle, lastPage, "sig");
                }




                if (p_certificateFile == "" || p_certificateFile == null)
                {
                    //
                    // smart-card certificate
                    //
                    IExternalSignature pkes = new X509Certificate2Signature(pk, digestAlgorithm);
                    MakeSignature.SignDetached(
                        appearance,
                        pkes, chain,
                        crlList, ocspClient, tsaClient,
                        estimatedSize,
                        subfilter);
                }
                else
                {
                    //
                    // file certificate .. @"c:\Eris\Certificati\certificate.pfx"
                    //
                    FileStream certStream = new FileStream(p_certificateFile, FileMode.Open);
                    Pkcs12Store pk12 = new Pkcs12Store(certStream, p_certificatePassword.ToCharArray());
                    certStream.Dispose();
                    // then Iterate throught certificate entries to find the private key entry
                    string alias = null;
                    foreach (string tAlias in pk12.Aliases) {
                        if (pk12.IsKeyEntry(tAlias)) {
                            alias = tAlias;
                            break;
                        }
                    }
                    var pks2 = pk12.GetKey(alias).Key;

                    IExternalSignature es = new PrivateKeySignature(pks2, "SHA-256");
                    MakeSignature.SignDetached(
                        appearance,
                        es, new X509Certificate[] { pk12.GetCertificate(alias).Certificate },
                        null, null, null,
                        0,
                        CryptoStandard.CMS);
                }

                // su finally
                if (reader != null) reader.Close();
                if (stamper != null) stamper.Close();
                if (writer != null) writer.Close();

                return true;
            }
            catch (Exception ex) {
            	MessageBox.Show("Firma digitale, errore: \n"+ex.Message+"\n\n["+ex.InnerException+"]");
                return false;
            }
            /*
            finally {

                if (reader != null)
                    reader.Close();
                if (stamper != null)
                    stamper.Close();
                if (writer != null)
                    writer.Close();
            }
            */
        }



        public bool SignPdf(string pdfSrc, string pdfDest)
        {
            // certificati personali
            X509Store x509Store = new X509Store("My");
            x509Store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certificates = x509Store.Certificates;

            IList<X509Certificate> chain = new List<X509Certificate>();
            X509Certificate2 pk = null;

            // la ricerca del certificato può essere fatta col methodo Find
            // ma risulta meno versatile di una ricerca ad hoc
            //
            //certificates.Find(X509FindType.FindBySubjectName, p_certificateIdentifier, p_validOnly);
            //certificates.Find(X509FindType.FindBySerialNumber, p_certificateIdentifier, p_validOnly);
            //
            // ricerca del certificato tramite identificativo attribuito all'utente
            // altrimenti scegli un certificato dalla lista o prendi il primo se unico
            //
            if (p_certificateIdentifier == "" || p_certificateIdentifier==null)
            {
                // identificativo non presente, scegli certificato
                if (certificates.Count > 1) {
                    SignSelectBox dlg = new SignSelectBox(certificates);
                    if (dlg.ShowDialog() == DialogResult.OK)
                    {
                        pk = certificates[dlg.Index];
                    }
                    else
                    {
                        return false;           // cancel
                    }
                }
                else
                {
                    // solo uno, prendi quello
                    pk = certificates[0];
                }
            }
            else {
                // cerca il certificato nello store per "identifier" 
                foreach (var cert in certificates)
                {
                    //if (!cert.Subject.Contains("dnQualifier"))
                    //    continue;   //no Sign certificate (Aruba)
                    if (cert.NotAfter <= DateTime.Now)
                        continue;   //Chain Certificate is Expired

                    if (cert.Subject.Contains(p_certificateIdentifier))
                    {
                        pk = cert;
                        break;
                    }
                }
            }
            if (pk == null)
            {
                // certificato non trovato ... fai scegliere

                //MessageBox.Show("Certificato firma digitale non trovato. Subject:\n" + p_certificateIdentifier);
                //return false;

                if (certificates.Count > 1)
                {
                    SignSelectBox dlg = new SignSelectBox(certificates);
                    if (dlg.ShowDialog() == DialogResult.OK)
                        pk = certificates[dlg.Index];
                    else
                        return false;           // cancel
                }
                else
                    return false;           // cancel

            }
            // build cert chain
            X509Chain x509chain = new X509Chain();
            x509chain.Build(pk);
            foreach (X509ChainElement x509ChainElement in x509chain.ChainElements) {
                chain.Add(DotNetUtilities.FromX509Certificate(x509ChainElement.Certificate));
            }
            //
            x509Store.Close();

            if (chain.Count == 0) {
                MessageBox.Show("Chain chiave privata nulla. Subject:\n" + p_certificateIdentifier);
                return false;
            }

            IOcspClient ocspClient = new OcspClientBouncyCastle(null);
            ITSAClient tsaClient = null;
            for (int i = 0; i < chain.Count; i++) {
                X509Certificate cert = chain[i];
                String tsaUrl = CertificateUtil.GetTSAURL(cert);
                if (tsaUrl != null) {
                    tsaClient = new TSAClientBouncyCastle(tsaUrl);
                    break;
                }
            }
            IList<ICrlClient> crlList = new List<ICrlClient>();
            crlList.Add(new CrlClientOnline(chain));



            return 
            Sign(pdfSrc, pdfDest,
            	chain, pk,
             	DigestAlgorithms.SHA256, CryptoStandard.CMS,
                p_reason,
                p_location,
                crlList, ocspClient, tsaClient, 0);
        }

    }
}
