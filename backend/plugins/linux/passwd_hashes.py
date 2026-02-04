# This file is Copyright 2025 LensAnalysis and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Linux password hash extraction plugin - Extract /etc/passwd and /etc/shadow from memory"""

import logging
from typing import List, Generator, Tuple, Optional, Iterable, Type

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist, mountinfo

vollog = logging.getLogger(__name__)


class PasswdHashes(interfaces.plugins.PluginInterface):
    """Extracts /etc/passwd and /etc/shadow files from Linux memory samples."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.StringRequirement(
                name="filter",
                description="Filter by username pattern (optional)",
                optional=True,
            ),
        ]

    @classmethod
    def _extract_file_content(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        inode: interfaces.objects.ObjectInterface,
        file_path: str,
    ) -> Optional[str]:
        """Extract file contents from inode's page cache.

        Args:
            context: The context to operate on
            kernel_module_name: The kernel module name
            inode: The inode object
            file_path: The file path for logging

        Returns:
            The file content as string if successful, None otherwise
        """
        if not inode.is_valid():
            return None

        if not inode.is_reg:
            return None

        file_size = int(inode.i_size)
        if file_size <= 0:
            return None

        # Check if page cache has any pages for this inode
        if not (inode.i_mapping and inode.i_mapping.is_readable()):
            return None

        nrpages = inode.i_mapping.member("nrpages")
        if not nrpages or int(nrpages) <= 0:
            return None

        # Get the kernel layer for page size
        kernel = context.modules[kernel_module_name]
        kernel_layer = context.layers[kernel.layer_name]

        try:
            content_bytes = b''

            # Extract content from page cache
            for page_index, page_content in inode.get_contents():
                # Calculate file offset
                current_fp = page_index * kernel_layer.page_size

                # Boundary check: ensure page is within file bounds
                max_length = file_size - current_fp
                if max_length <= 0:
                    continue

                # Truncate page content to file size
                page_bytes_len = min(max_length, len(page_content))
                if current_fp >= file_size:
                    continue

                page_bytes = page_content[:page_bytes_len]
                content_bytes += page_bytes

            # Try to decode as text
            try:
                return content_bytes.decode('utf-8', errors='replace')
            except:
                return content_bytes.decode('latin-1', errors='replace')

        except exceptions.InvalidAddressException as e:
            vollog.debug(f"Failed to extract file {file_path}: {e}")
            return None
        except Exception as e:
            vollog.error(f"Error reading file {file_path}: {e}")
            return None

    def _get_super_blocks(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
    ) -> Generator[Tuple[interfaces.objects.ObjectInterface, str], None, None]:
        """Get all super_blocks from the kernel using mountinfo.

        Args:
            context: The context to operate on
            kernel_module_name: The kernel module name

        Yields:
            Tuples of (super_block, mountpoint)
        """
        # Use MountInfo.get_superblocks() to get superblocks
        for superblock, mountpoint in mountinfo.MountInfo.get_superblocks(
            context=context,
            vmlinux_module_name=kernel_module_name,
        ):
            yield superblock, mountpoint

    def _find_file_in_dentry_tree(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        dentry: interfaces.objects.ObjectInterface,
        base_path: str,
        target_file: str,
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Find a specific file in a dentry tree.

        Args:
            context: The context to operate on
            kernel_module_name: The kernel module name
            dentry: The root dentry to start from
            base_path: The base path for this filesystem
            target_file: The target file name to find

        Returns:
            The dentry of the target file if found, None otherwise
        """
        from collections import deque

        seen = set()
        queue = deque([dentry])

        while queue:
            current_dentry = queue.popleft()

            # Avoid cycles
            if current_dentry.vol.offset in seen:
                continue
            seen.add(current_dentry.vol.offset)

            try:
                # Get the file path
                try:
                    file_path = base_path + current_dentry.path()
                except exceptions.InvalidAddressException:
                    continue

                # Check if this is the target file
                if file_path == target_file:
                    return current_dentry

                # Add subdirectories to queue (limit depth)
                if current_dentry.d_inode and current_dentry.d_inode.is_reg:
                    continue  # Don't recurse into files

                try:
                    for subdir in current_dentry.get_subdirs():
                        queue.append(subdir)
                except exceptions.InvalidAddressException:
                    continue
                except:
                    continue

            except exceptions.InvalidAddressException:
                continue

        return None

    def _generator(self) -> Generator[Tuple, None, None]:
        kernel = self.context.modules[self.config["kernel"]]

        filter_pattern = self.config.get("filter", None)

        # Target files to extract
        target_files = ['/etc/passwd', '/etc/shadow']
        found_files = {}

        # Walk all super_blocks looking for target files
        for super_block, mountpoint in self._get_super_blocks(self.context, self.config["kernel"]):
            try:
                # Get the root dentry for this filesystem
                root_dentry = super_block.s_root
                if not root_dentry or not root_dentry.is_readable():
                    continue

                # Look for each target file
                for target_file in target_files:
                    if target_file in found_files:
                        continue  # Already found

                    # Only search if mountpoint is relevant (root or contains /etc)
                    if mountpoint == '/' or mountpoint.startswith('/'):
                        target_dentry = self._find_file_in_dentry_tree(
                            self.context,
                            self.config["kernel"],
                            root_dentry,
                            mountpoint if mountpoint else '/',
                            target_file
                        )

                        if target_dentry:
                            # Get the inode
                            inode = target_dentry.get_inode()
                            if inode:
                                found_files[target_file] = inode
                                vollog.info(f"Found {target_file} at mountpoint {mountpoint}")

            except exceptions.InvalidAddressException:
                continue

        # Extract and display the files
        for file_path in ['/etc/passwd', '/etc/shadow']:
            if file_path not in found_files:
                # Try to find via pagecache.Files approach
                vollog.warning(f"{file_path} not found in dentry tree")
                continue

            inode = found_files[file_path]
            content = self._extract_file_content(
                self.context,
                self.config["kernel"],
                inode,
                file_path
            )

            if content:
                # Parse and display content
                if '/passwd' in file_path:
                    # Parse /etc/passwd
                    for line in content.split('\n'):
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue

                        parts = line.split(':')
                        if len(parts) >= 7:
                            username = parts[0]

                            # Apply filter if specified
                            if filter_pattern:
                                import re
                                try:
                                    if not re.search(filter_pattern, username, re.IGNORECASE):
                                        continue
                                except re.error:
                                    pass

                            yield (0, (
                                file_path,
                                username,
                                parts[1],  # password placeholder (usually 'x')
                                parts[2],  # UID
                                parts[3],  # GID
                                parts[4],  # GECOS
                                parts[5],  # home directory
                                parts[6],  # shell
                            ))

                elif '/shadow' in file_path:
                    # Parse /etc/shadow
                    for line in content.split('\n'):
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue

                        parts = line.split(':')
                        if len(parts) >= 9:
                            username = parts[0]

                            # Apply filter if specified
                            if filter_pattern:
                                import re
                                try:
                                    if not re.search(filter_pattern, username, re.IGNORECASE):
                                        continue
                                except re.error:
                                    pass

                            yield (0, (
                                file_path,
                                username,
                                parts[1],  # password hash
                                parts[2],  # last password change
                                parts[3],  # minimum password age
                                parts[4],  # maximum password age
                                parts[5],  # password warning period
                                parts[6],  # password inactivity period
                                parts[7],  # account expiration date
                                parts[8],  # reserved field
                            ))
            else:
                yield (0, (
                    file_path,
                    'ERROR',
                    'File not in page cache or could not be extracted',
                    '',
                    '',
                    '',
                    '',
                    '',
                ))

    def run(self):
        return renderers.TreeGrid(
            [
                ("File", str),
                ("Username", str),
                ("Hash/Password", str),
                ("Field 3", str),
                ("Field 4", str),
                ("Field 5", str),
                ("Field 6", str),
                ("Field 7", str),
                ("Field 8", str),
            ],
            self._generator(),
        )
