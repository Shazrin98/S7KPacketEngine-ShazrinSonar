using System;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;

namespace ShazrinSonar
{
    public static class SecurityManager
    {
        /// Generates a cross-platform 16-character Hardware Fingerprint. Compatible with Windows, macOS, and Linux natively.
        public static string GenerateHardwareId()
        {
            try
            {
                // 1. Get primary physical Network Interface MAC Address (Cross-Platform)
                string primaryMac = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(nic => nic.OperationalStatus == OperationalStatus.Up &&
                                  nic.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                                  nic.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                    .Select(nic => nic.GetPhysicalAddress().ToString())
                    .FirstOrDefault(mac => !string.IsNullOrEmpty(mac) && mac != "000000000000") 
                    ?? "SHAZRIN-GENERIC-MAC";

                // 2. Combine MAC with CPU threads, Machine Name, and OS Platform
                string rawHardwareString = $"{primaryMac}-{Environment.MachineName}-{Environment.ProcessorCount}-{Environment.OSVersion.Platform}";

                // 3. Compute SHA256 Hash and truncate to 16 hex characters
                using var sha256 = SHA256.Create();
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawHardwareString));
                return string.Concat(hashBytes.Take(8).Select(b => b.ToString("X2")));
            }
            catch
            {
                return "SHAZRIN-HWID-FALLBACK";
            }
        }

        /// Validates offline license authorization via local .lic file or removable USB drive.
        /// Return "true" or "false" to test authorization
        public static bool ValidateAuthorization(string expectedKey)
        {
            string currentHwid = GenerateHardwareId();
            string licenseFile = "ShazrinSonar.lic";

            // 1. Check local .lic file in working directory
            if (File.Exists(licenseFile))
            {
                string licContent = File.ReadAllText(licenseFile).Trim();
                if (licContent.Equals(currentHwid, StringComparison.OrdinalIgnoreCase) || 
                    licContent.Equals(expectedKey, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            // 2. Check plugged-in USB key (Cross-platform DriveInfo query)
            try
            {
                foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Removable && d.IsReady))
                {
                    string usbLicPath = Path.Combine(drive.RootDirectory.FullName, "ShazrinSonar.lic");
                    if (File.Exists(usbLicPath))
                    {
                        string usbContent = File.ReadAllText(usbLicPath).Trim();
                        if (usbContent.Equals(currentHwid, StringComparison.OrdinalIgnoreCase) || 
                            usbContent.Equals(expectedKey, StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }
                }
            }
            catch { }

            // Write host HWID to local file on first boot for easy setup
            try 
            { 
                // This line is to write host HWID to local file on first boot for easy setup
                // File.WriteAllText(licenseFile, currentHwid); 

                // This line is to write host HWID to local file for reference, but DO NOT grant access
                File.WriteAllText("Your_Hardware_ID.txt", $"Provide this ID to your developer to receive a license key:\n{currentHwid}");
            } 
            catch { }

            // Hard-lock the application with "false". Use "true" for testing without license.
            return false;
        }
    }
}