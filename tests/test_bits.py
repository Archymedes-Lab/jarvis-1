"""BITS updater allowlisting is matched on the host, not on a substring.

Two bugs in one: OneDrive's real job (DisplayName `PreSignInSettingsConfigJSON`,
url `https://g.live.com/odclientsettings/ProdV2`) contains none of the vendor
words and was reported HIGH, while `https://evil.example/x.ps1?ref=onedrive`
contained one and was exempt. The first is noise; the second is an allowlist a
dropper can opt into by choosing a query string.
"""

import unittest

from jarvis.collectors.host.intrusion import _bits_hosts, _bits_is_vendor


class BitsVendorTests(unittest.TestCase):
    def test_the_real_onedrive_presignin_job_is_not_a_finding(self):
        self.assertTrue(_bits_is_vendor(
            "PreSignInSettingsConfigJSON",
            "https://g.live.com/odclientsettings/ProdV2"))

    def test_the_same_job_with_an_update_query_string_is_also_fine(self):
        self.assertTrue(_bits_is_vendor(
            "PreSignInSettingsConfigJSON",
            "https://g.live.com/odclientsettings/ProdV2?OneDriveUpdate=d5ca958f"))

    def test_a_vendor_word_in_the_url_does_not_exempt_a_foreign_host(self):
        self.assertFalse(_bits_is_vendor(
            "stager", "https://evil.example/payload.ps1?ref=onedrive"))

    def test_a_vendor_job_name_does_not_exempt_a_foreign_host(self):
        self.assertFalse(_bits_is_vendor(
            "Windows Update", "https://evil.example/a.exe"))

    def test_one_foreign_host_among_several_defeats_the_exemption(self):
        self.assertFalse(_bits_is_vendor(
            "MicrosoftEdgeUpdate",
            "https://g.live.com/ok ; https://evil.example/bad"))

    def test_a_job_with_no_url_falls_back_to_the_name(self):
        self.assertTrue(_bits_is_vendor("Windows Update", ""))
        self.assertFalse(_bits_is_vendor("SomeJob", ""))

    def test_every_host_in_the_file_list_is_extracted_lowercased_and_portless(self):
        # The port is dropped deliberately: the vendor pattern is anchored at
        # the end of the host, so a `:8080` suffix would silently defeat every
        # match rather than tighten it.
        self.assertEqual(
            _bits_hosts("https://A.example/x ; http://b.example:8080/y"),
            ["a.example", "b.example"])


if __name__ == "__main__":
    unittest.main()
