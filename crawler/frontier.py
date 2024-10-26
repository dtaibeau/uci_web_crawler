import os
import shelve

from threading import Thread, RLock
from queue import Queue, Empty

from utils import get_logger, get_urlhash, normalize
from scraper import is_valid
import logging


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Frontier(object):
    def __init__(self, config, restart):
        self.logger = get_logger("FRONTIER")
        self.config = config
        # MT edit: only 1 thread can modify shared state at a time (e.g. save file)
        self.lock = RLock() 
        # MT edit: changed to queue for thread-safe DS
        self.to_be_downloaded = Queue() 
        
        if not os.path.exists(self.config.save_file) and not restart:
            # Save file does not exist, but request to load save.
            self.logger.info(
                f"Did not find save file {self.config.save_file}, "
                f"starting from seed.")
        elif os.path.exists(self.config.save_file) and restart:
            # Save file does exists, but request to start from seed.
            self.logger.info(
                f"Found save file {self.config.save_file}, deleting it.")
            os.remove(self.config.save_file)
        # Load existing save file, or create one if it does not exist.
        self.save = shelve.open(self.config.save_file)
        
        if restart:
            for url in self.config.seed_urls:
                self.add_url(url)
        else:
            # Set the frontier state with contents of save file.
            self._parse_save_file()
            if not self.save:
                for url in self.config.seed_urls:
                    self.add_url(url)

    def mark_url_complete(self, url, low_information=False):
        """
        Mark the URL as complete in the frontier.

        Args:
            url (str): The URL to mark as complete.
            low_information (bool): Whether the URL is low-information.
        """
        urlhash = get_urlhash(url)
        with self.lock:
            if urlhash in self.save:
                self.save[urlhash] = (url, True)
                if low_information:
                    logger.info(f"Marked low-information URL as complete: {url}")
            else:
                logger.error(f"Attempted to complete unknown URL: {url}")


    def _parse_save_file(self):
        ''' This function can be overridden for alternate saving techniques. '''
        total_count = len(self.save)
        tbd_count = 0
        with self.lock: # MT edit
            for url, completed in self.save.values():
                if not completed and is_valid(url):
                    self.to_be_downloaded.put(url)
                    tbd_count += 1
        self.logger.info(
            f"Found {tbd_count} urls to be downloaded from {total_count} "
            f"total urls discovered.")

    def get_tbd_url(self):
        try:
            # MT edit: retrieves URLs in non-blocking manner
            return self.to_be_downloaded.get_nowait()
        except IndexError:
            return None

    def add_url(self, url):
        url = normalize(url)
        urlhash = get_urlhash(url)
        with self.lock: # MT edit
            if urlhash not in self.save:
                self.save[urlhash] = (url, False)
                self.save.sync()
                self.to_be_downloaded.put(url)
    
    def mark_url_complete(self, url):
        urlhash = get_urlhash(url)
        with self.lock:
            if urlhash not in self.save:
                # This should not happen.
                self.logger.error(
                    f"Completed url {url}, but have not seen it before.")

        self.save[urlhash] = (url, True)
        self.save.sync()
