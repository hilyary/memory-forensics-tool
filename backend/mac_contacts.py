#!/usr/bin/env python3
# macOS Contacts Plugin for Volatility 3
# This plugin attempts to find contact information from macOS memory images

import logging
from typing import List, Tuple, Any, Generator

from volatility3.framework import interfaces, exceptions, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import mac
from volatility3.framework.layers import scanners

vollog = logging.getLogger(__name__)


class Mac_contacts(plugins.PluginInterface):
    """Recovers contact information from macOS memory."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Kernel module for the OS",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="macutils", component=mac.MacUtilities, version=(1, 0, 0)
            ),
            requirements.StringRequirement(
                name="keyword",
                description="Search keyword for contact data (optional)",
                optional=True,
            ),
            requirements.IntRequirement(
                name="max-results",
                description="Maximum number of results to return",
                optional=True,
                default=100,
            ),
        ]

    def _generator(self) -> Generator[Tuple[int, Tuple[str, str, str, str]], None, None]:
        kernel = self.context.modules[self.config["kernel"]]

        # Get physical layer for scanning
        layer_name = kernel.layer_name
        layer = self.context.layers[layer_name]

        # Search for email patterns
        email_scanner = scanners.RegExScanner(b'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}')

        # Search for phone number patterns (various formats)
        phone_scanner = scanners.RegExScanner(
            b'\\+?\\d{1,3}?[-.\\s]?\\(?\\d{1,4}\\)?[-.\\s]?\\d{1,4}[-.\\s]?\\d{1,9}'
        )

        # Search for URL patterns
        url_scanner = scanners.RegExScanner(
            b'https?://[A-Za-z0-9.-]+(?:[/][^\\s]*)?'
        )

        found_results = 0
        max_results = self.config.get("max-results", 100)

        # Scan for emails
        for offset, value in layer.scan(context=self.context, scanner=email_scanner):
            if found_results >= max_results:
                break

            try:
                email = value.decode('utf-8', errors='ignore').strip()
                if self._is_valid_email(email):
                    yield (0, (
                        format_hints.Hex(offset),
                        "Email",
                        email,
                        ""
                    ))
                    found_results += 1
            except Exception as e:
                vollog.debug(f"Error parsing email at {offset}: {e}")

        # Scan for phone numbers
        if found_results < max_results:
            for offset, value in layer.scan(context=self.context, scanner=phone_scanner):
                if found_results >= max_results:
                    break

                try:
                    phone = value.decode('utf-8', errors='ignore').strip()
                    if self._is_valid_phone(phone):
                        yield (0, (
                            format_hints.Hex(offset),
                            "Phone",
                            phone,
                            ""
                        ))
                        found_results += 1
                except Exception as e:
                    vollog.debug(f"Error parsing phone at {offset}: {e}")

        # Scan for URLs (potential contact-related)
        if found_results < max_results:
            for offset, value in layer.scan(context=self.context, scanner=url_scanner):
                if found_results >= max_results:
                    break

                try:
                    url = value.decode('utf-8', errors='ignore').strip()
                    if self._is_contact_url(url):
                        yield (0, (
                            format_hints.Hex(offset),
                            "URL",
                            url,
                            ""
                        ))
                        found_results += 1
                except Exception as e:
                    vollog.debug(f"Error parsing URL at {offset}: {e}")

    def _is_valid_email(self, email: str) -> bool:
        """Basic email validation"""
        if not email or len(email) > 254:
            return False
        if '@' not in email or email.count('@') != 1:
            return False
        local, domain = email.rsplit('@', 1)
        if not local or not domain:
            return False
        if '.' not in domain:
            return False
        return True

    def _is_valid_phone(self, phone: str) -> bool:
        """Basic phone validation - must have at least 7 digits"""
        digits = ''.join(c for c in phone if c.isdigit())
        return len(digits) >= 7 and len(digits) <= 15

    def _is_contact_url(self, url: str) -> bool:
        """Check if URL might be contact-related"""
        contact_keywords = [b'linkedin', b'facebook', b'twitter', b'instagram',
                          b'github', b'telegram', b'whatsapp', b'skype']
        url_lower = url.lower()
        return any(keyword.decode() in url_lower for keyword in contact_keywords)

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Type", str),
                ("Value", str),
                ("Notes", str),
            ],
            self._generator(),
        )
