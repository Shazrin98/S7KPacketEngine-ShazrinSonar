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
                // 1. Get primary physical Network Interface MAC Address (Stable, ignores current connection status)
                string primaryMac = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(nic => nic.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                                  nic.NetworkInterfaceType != NetworkInterfaceType.Tunnel &&
                                  !nic.Description.ToLower().Contains("virtual") &&
                                  !nic.Description.ToLower().Contains("pseudo"))
                    // Prioritize physical Ethernet, then Wireless
                    .OrderBy(nic => nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet ? 0 : 1)
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
        public static bool ValidateAuthorization(string expectedKey)
        {
            string currentHwid = GenerateHardwareId();
            string fileName = "ShazrinSonar.lic";

            // Check both the directory where the EXE lives, and the current working directory
            string[] searchPaths = {
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, fileName),
                Path.Combine(Environment.CurrentDirectory, fileName)
            };

            // 1. Check local .lic files
            foreach (string licensePath in searchPaths)
            {
                if (File.Exists(licensePath))
                {
                    string licContent = File.ReadAllText(licensePath).Trim();
                    if (licContent.Equals(currentHwid, StringComparison.OrdinalIgnoreCase) || 
                        licContent.Equals(expectedKey, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }

            // 2. Check plugged-in USB key (Cross-platform DriveInfo query)
            try
            {
                foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Removable && d.IsReady))
                {
                    string usbLicPath = Path.Combine(drive.RootDirectory.FullName, fileName);
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

            // Write host HWID to local file so you know exactly what ID it is expecting
            try 
            { 
                string outputTxt = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Your_Hardware_ID.txt");
                File.WriteAllText(outputTxt, $"Provide this ID to your developer to receive a license key:\n{currentHwid}");
            } 
            catch { }

            // Hard-lock the application to enforce the license check
            return false;
        }
    }
}