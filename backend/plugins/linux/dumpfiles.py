# This file is Copyright 2025 LensAnalysis and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Linux file extraction plugin - Dump cached files from Linux memory samples

This plugin extracts files from the Linux page cache, similar to the Windows
dumpfiles plugin. It walks all mounted filesystems and extracts any cached
file contents.
"""

import logging
import os
from typing import List, Generator, Tuple, Optional, Iterable, Type

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist, mountinfo

vollog = logging.getLogger(__name__)


class DumpFiles(interfaces.plugins.PluginInterface):
    """Dumps cached file contents from Linux memory samples."""

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
            requirements.BooleanRequirement(
                name="dump",
                description="Actually extract files to disk",
                default=True,
                optional=True,
            ),
            requirements.StringRequirement(
                name="filter",
                description="Only dump files matching this filter pattern",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="ignore-case",
                description="Ignore case when matching filter",
                default=False,
                optional=True,
            ),
            requirements.IntRequirement(
                name="pid",
                description="Filter by specific process ID (uses process's root fs)",
                optional=True,
            ),
        ]

    @classmethod
    def _walk_dentry_tree(
        cls,
        dentry: interfaces.objects.ObjectInterface,
        max_depth: int = 100,
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Recursively walk dentry tree starting from the given dentry.

        Args:
            dentry: The starting dentry
            max_depth: Maximum recursion depth to prevent infinite loops

        Yields:
            dentry objects in the tree
        """
        if max_depth <= 0:
            return

        seen = set()

        def _walk(current_dentry, depth):
            if depth <= 0:
                return

            # Avoid cycles
            if current_dentry.vol.offset in seen:
                return
            seen.add(current_dentry.vol.offset)

            # Yield current dentry
            yield current_dentry

            # Walk subdirectories
            try:
                for subdir in current_dentry.get_subdirs():
                    yield from _walk(subdir, depth - 1)
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Failed to walk subdirs for dentry at {current_dentry.vol.offset:#x}"
                )

        yield from _walk(dentry, max_depth)

    @classmethod
    def _extract_file_from_inode(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        inode: interfaces.objects.ObjectInterface,
        file_path: str,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
    ) -> Optional[str]:
        """Extract file contents from inode's page cache.

        Args:
            context: The context to operate on
            kernel_module_name: The kernel module name
            inode: The inode object
            file_path: The file path for output naming
            open_method: The file handler class

        Returns:
            The output filename if successful, None otherwise
        """
        if not inode.is_valid():
            return None

        if not inode.is_reg:
            # Only extract regular files
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

        # Generate output filename
        inode_num = int(inode.i_ino)
        safe_filename = open_method.sanitize_filename(
            f"file.{inode_num:#x}.{os.path.basename(file_path)}"
        )

        # Get the kernel layer for page size
        kernel = context.modules[kernel_module_name]
        kernel_layer = context.layers[kernel.layer_name]

        try:
            with open_method(safe_filename) as file_handle:
                bytes_written = 0
                stream_initialized = False

                # Extract content from page cache
                for page_index, page_content in inode.get_contents():
                    # Calculate file offset
                    current_fp = page_index * kernel_layer.page_size

                    # Boundary check: ensure page is within file bounds
                    max_length = file_size - current_fp
                    if max_length <= 0:
                        # Page is beyond file end
                        continue

                    # Truncate page content to file size
                    page_bytes_len = min(max_length, len(page_content))
                    if current_fp >= file_size:
                        vollog.debug(
                            f"Page out of file bounds: inode {inode.vol.offset:#x}, "
                            f"inode size {file_size}, page index {page_index}"
                        )
                        continue

                    page_bytes = page_content[:page_bytes_len]

                    # Lazy initialization: truncate to create sparse file
                    if not stream_initialized:
                        file_handle.truncate(file_size)
                        stream_initialized = True

                    # Seek to the correct position and write
                    file_handle.seek(current_fp)
                    file_handle.write(page_bytes)
                    bytes_written += len(page_bytes)

                if bytes_written == 0:
                    vollog.debug(f"No data extracted for inode {inode_num:#x}")
                    return None

                vollog.debug(f"Extracted {bytes_written} bytes to {safe_filename}")
                return file_handle.preferred_filename

        except exceptions.InvalidAddressException as e:
            vollog.debug(f"Failed to extract file {file_path}: {e}")
            return None
        except Exception as e:
            vollog.error(f"Error writing file {safe_filename}: {e}")
            return None

    @classmethod
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

    @classmethod
    def _dump_files_from_dentry(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        dentry: interfaces.objects.ObjectInterface,
        base_path: str,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
        filter_pattern: Optional[str] = None,
        ignore_case: bool = False,
        dump: bool = False,
    ) -> Generator[Tuple, None, None]:
        """Dump files from a dentry tree.

        Args:
            context: The context to operate on
            kernel_module_name: The kernel module name
            dentry: The root dentry to start from
            base_path: The base path for this filesystem
            open_method: The file handler class
            filter_pattern: Optional regex filter pattern
            ignore_case: Whether to ignore case in filter matching
            dump: If True, extract files to disk; if False, only list them

        Yields:
            Tuples of (file_path, inode_number, file_size, result_file)
        """
        import re

        regex = None
        if filter_pattern:
            flags = re.IGNORECASE if ignore_case else 0
            try:
                regex = re.compile(filter_pattern, flags)
            except re.error as e:
                vollog.error(f"Invalid filter pattern '{filter_pattern}': {e}")
                return

        for current_dentry in cls._walk_dentry_tree(dentry):
            try:
                # Get the inode
                inode = current_dentry.get_inode()
                if not inode:
                    continue

                # Get the file path
                try:
                    file_path = base_path + current_dentry.path()
                except exceptions.InvalidAddressException:
                    file_path = f"{base_path}/unknown"

                # Apply filter if specified
                if regex and not regex.search(file_path):
                    continue

                # Only extract regular files
                if not inode.is_reg:
                    continue

                file_size = int(inode.i_size)
                inode_num = int(inode.i_ino)

                # If dump=False, only list files without extracting
                if not dump:
                    # Check if file is in cache (has cached pages)
                    if inode.i_mapping and inode.i_mapping.nrpages > 0:
                        cached_pages = int(inode.i_mapping.nrpages)
                        yield (file_path, inode_num, file_size, f"In cache ({cached_pages} pages)")
                    else:
                        yield (file_path, inode_num, file_size, "Not in cache")
                    continue

                # Try to extract the file
                result_file = cls._extract_file_from_inode(
                    context, kernel_module_name, inode, file_path, open_method
                )

                if result_file:
                    yield (file_path, inode_num, file_size, result_file)
                else:
                    # Still report the file even if extraction failed
                    yield (file_path, inode_num, file_size, "Not in cache")

            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Invalid address accessing dentry at {current_dentry.vol.offset:#x}"
                )
                continue

    def _generator(self) -> Generator[Tuple, None, None]:
        kernel = self.context.modules[self.config["kernel"]]

        filter_pattern = self.config.get("filter", None)
        ignore_case = self.config.get("ignore-case", False)
        dump = self.config.get("dump", True)  # 默认 True，与 requirements 一致

        # Get reference task for path resolution
        filter_func = pslist.PsList.create_pid_filter(
            [self.config.get("pid", None)]
        )
        tasks = pslist.PsList.list_tasks(
            self.context, self.config["kernel"], filter_func=filter_func
        )

        # Get the first task (used if pid filter is specified)
        try:
            ref_task = next(tasks)
        except StopIteration:
            vollog.error("No tasks found to use as reference")
            return
        except exceptions.InvalidAddressException as e:
            vollog.error(f"Failed to get reference task fs info: {e}")
            return

        # Walk all super_blocks
        for super_block, mountpoint in self._get_super_blocks(self.context, self.config["kernel"]):
            try:
                # Get the root dentry for this filesystem
                root_dentry = super_block.s_root
                if not root_dentry or not root_dentry.is_readable():
                    continue

                # Use the mountpoint from get_superblocks
                mount_path = mountpoint if mountpoint else "/unknown"

                # Extract files from this filesystem
                for result in self._dump_files_from_dentry(
                    self.context,
                    self.config["kernel"],
                    root_dentry,
                    mount_path,
                    self.open,
                    filter_pattern,
                    ignore_case,
                    dump,
                ):
                    file_path, inode_num, file_size, result_file = result
                    yield (
                        0,
                        (
                            file_path,
                            format_hints.Hex(inode_num),
                            file_size,
                            result_file,
                        ),
                    )

            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Invalid address accessing super_block at {super_block.vol.offset:#x}"
                )
                continue

    def run(self):
        return renderers.TreeGrid(
            [
                ("File Path", str),
                ("Inode", format_hints.Hex),
                ("Size", int),
                ("Result", str),
            ],
            self._generator(),
        )
