using iText;

namespace PdfSign
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Pdf File Signature");
            Console.WriteLine("This program is free and open source, it uses iTextSharp signature features.");
            Console.WriteLine("It is released under the AGPL licence.");

            if (args.Length == 0)
            {
                Console.WriteLine("Please provide a file path.");
                return;
            }
            string filePath = args[0];
            if (!File.Exists(filePath))
            {
                Console.WriteLine($"File not found: {filePath}");
                return;
            }
            if (Path.GetExtension(filePath).ToLower() != ".pdf")
            {
                Console.WriteLine("The provided file is not a PDF.");
                return;
            }

            // Perform signing operation

            string name = Path.GetFileNameWithoutExtension(filePath);
            if (string.IsNullOrEmpty(name))
            {
                Console.WriteLine("Invalid file name.");
                return;
            }

            string folder = Path.GetDirectoryName(filePath);
            if(string.IsNullOrEmpty(folder))
            {
                folder = @".\";
            }

            string signedFilePath = Path.Combine(folder, $"{name}.signed.pdf");

            PdfDigitalSign sign = new PdfDigitalSign();
            sign.SignPdf(filePath, signedFilePath);
            Console.WriteLine($"Signed PDF file created at: {signedFilePath}");

        }
    }
}
