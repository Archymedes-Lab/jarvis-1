import unittest

from jarvis.core import vet


class SharedInfrastructureTests(unittest.TestCase):
    def test_vendor_service_domains_are_not_attacker_indicators(self):
        for domain in (
            "chatgpt.com",
            "ab.chatgpt.com",
            "assets.claude.ai",
            "cloudflare-dns.com",
            "canary.netmon.azure.com",
        ):
            with self.subTest(domain=domain):
                self.assertIsNone(vet.vet_domain(domain)[0])

    def test_cloudflare_anycast_address_is_not_tenant_specific(self):
        value, reason = vet.vet_ipv4("188.114.97.3")

        self.assertIsNone(value)
        self.assertIn("Cloudflare", reason)

    def test_github_shared_edge_address_is_not_tenant_specific(self):
        for address in ("185.199.108.153", "185.199.111.133", "192.30.252.154"):
            with self.subTest(address=address):
                value, reason = vet.vet_ipv4(address)
                self.assertIsNone(value)
                self.assertIn("GitHub", reason)

    def test_address_next_to_github_edge_remains_eligible(self):
        self.assertEqual(vet.vet_ipv4("185.199.112.1")[0], "185.199.112.1")
        self.assertEqual(vet.vet_ipv4("192.30.252.155")[0], "192.30.252.155")

    def test_os_connectivity_checks_are_not_indicators(self):
        for domain in ("ipv6.msftconnecttest.com", "www.msftncsi.com",
                       "connectivitycheck.gstatic.com"):
            with self.subTest(domain=domain):
                self.assertIsNone(vet.vet_domain(domain)[0])
        self.assertEqual(vet.vet_domain("msftconnecttest.com.evil.io")[0],
                         "msftconnecttest.com.evil.io")

    def test_unrelated_public_address_remains_eligible(self):
        value, reason = vet.vet_ipv4("45.67.89.10")

        self.assertEqual(value, "45.67.89.10")
        self.assertEqual(reason, "")


if __name__ == "__main__":
    unittest.main()
