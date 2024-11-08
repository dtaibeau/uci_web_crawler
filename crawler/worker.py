from threading import Thread, RLock

from inspect import getsource
from utils.download import download
from utils import get_logger, get_urlhash
import scraper
import time


class Worker(Thread):
    def __init__(self, worker_id, config, frontier, domain_lock):
        self.worker_id = worker_id
        self.logger = get_logger(f"Worker-{worker_id}", "Worker")
        self.config = config
        self.frontier = frontier

        # MT edit: track the last access time per domain
        self.domain_access_times = {}  
        # MT edit: lock for domain tracking
        self.domain_lock = domain_lock  

        # basic check for requests in scraper
        assert {getsource(scraper).find(req) for req in {"from requests import", "import requests"}} == {-1}, "Do not use requests in scraper.py"
        assert {getsource(scraper).find(req) for req in {"from urllib.request import", "import urllib.request"}} == {-1}, "Do not use urllib.request in scraper.py"
        super().__init__(daemon=True)
        
    def run(self):
        while True:
            try:
                # get next URL to download from fontier
                tbd_url = self.frontier.get_tbd_url()
            except Exception as e: 
                self.logger.info("No URL available. Retrying...")
                time.sleep(1)
                continue

            if not tbd_url:
                self.logger.info("Frontier is empty. Stopping Crawler.")
                break

            domain = self._get_domain(tbd_url)
            with self.domain_lock:
                last_access_time = self.domain_access_times.get(domain, 0)
                time_since_last_access = time.time() - last_access_time

                if time_since_last_access < self.config.time_delay:
                    delay = self.config.time_delay - time_since_last_access
                    self.logger.info(
                        # respecting politeness
                        f"Worker-{self.worker_id} sleeping for {delay:.2f}s to respect politeness for {domain}"
                    )
                    time.sleep(delay)

                # update last access time for domain
                self.domain_access_times[domain] = time.time()
            try:
                # download URL in handle response
                resp = download(tbd_url, self.config, self.logger)
                if resp is not None:
                    if resp.status == 404 or resp.status == 403:
                        self.logger.info(f"404 NOT FOUND: {tbd_url}")
                        self.frontier.mark_url_complete(tbd_url)
                        continue
                    self.logger.info(
                        f"Downloaded {tbd_url}, status <{resp.status}>, "
                        f"using cache {self.config.cache_server}."
                    )

                # add scraped URLs to frontier
                scraped_urls = scraper.scraper(tbd_url, resp, self.frontier)
                if scraped_urls is None:
                    self.logger.error("No URLS to add")
                    return []
                
                for scraped_url in scraped_urls:
                    # MT edit: thread-safe frontier access
                    self.frontier.add_url(scraped_url)
            finally:
                # Mark URL as complete
                self.frontier.mark_url_complete(tbd_url)
    

    def _get_domain(self, url):
        # extract domain from URL for politeness tracking
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        return parsed_url.netloc
