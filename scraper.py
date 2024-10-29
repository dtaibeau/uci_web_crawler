import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import logging
import urllib.robotparser
from urllib.parse import urlparse
from collections import Counter
from report import is_unique_page, longest_page, common_words_count, num_subdomains

MAX_DEPTH = 5
MIN_WORD_COUNT = 50

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

robots_cache = {}

# abide by robots.txt
def can_fetch(url, user_agent='*'):
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    if base_url not in robots_cache:
        rp = urllib.robotparser.RobotFileParser()
        rp.set_url(f"{base_url}/robots.txt")
        rp.read()
        robots_cache[base_url] = rp
    
    return robots_cache[base_url].can_fetch(user_agent, url)


def is_empty_page(content):
    return len(content.strip()) == 0

def is_low_information(content):
    # extract words
    words = re.findall(r'\w+', content)
    
    # find urls
    hyperlinks = re.findall(r'https?://\S+|www\.\S+', content)
    
    # if less than min words and urls < 5 = low info page
    return len(words) < MIN_WORD_COUNT and len(hyperlinks) < 5

def scraper(url, resp, frontier):
    """
    Extracts and filters valid URLs from a page's response,
    handling cache server error codes (600-608) and updating report metrics.

    Args:
        url (str): The URL being processed.
        resp (utils.response.Response): The response object with the page content.
        frontier (Frontier): The frontier to mark URLs as complete.

    Returns:
        list: A list of valid URLs for further crawling.
    """
    # handle cache server error codes
    if 600 <= resp.status <= 608:
        handle_cache_server_error(url, resp, frontier)
        return []

    # check if response content is valid and meaningful
    content = resp.raw_response.content if resp.raw_response else ""
    if resp.status == 200 and (is_empty_page(content) or is_low_information(content)):
        logger.info(f"Skipping dead URL: {url} - 200 status but no content or low information")
        frontier.mark_url_complete(url, low_information=True)
        return []

    # update report metrics if the page is unique
    if is_unique_page(url):

        # update longest page information
        longest_page(url, content)

        # update common words count
        common_words_count(content)

        # update subdomain count
        num_subdomains(url)

    # extract links from the page content
    links = extract_next_links(url, resp)
    valid_links = []

    for link in links:
        if is_valid(link):
            depth = url.count('/')  
            if depth < MAX_DEPTH:
                valid_links.append(link)
            else:
                logger.info(f"Skipping {link} - Exceeded max depth")
    
    # don't reprocess
    frontier.mark_url_complete(url)
    return valid_links


def handle_cache_server_error(url, resp, frontier):
    """
    Handles specific cache server error codes (600-608).

    Args:
        url (str): The URL that caused the error.
        resp (utils.response.Response): The response object with the error code.
        frontier (Frontier): The frontier to mark URLs as complete.
    """
    status = resp.status
    if status == 600:
        logger.error(f"Malformed request for URL: {url}")
    elif status == 601:
        logger.error(f"Download exception for URL: {url}. Error: {resp.error}")
    elif status == 602:
        logger.error(f"Spacetime server failure for URL: {url}")
    elif status == 603:
        logger.info(f"Invalid scheme for URL: {url} (must be http or https)")
    elif status == 604:
        logger.info(f"Domain not within specification for URL: {url}")
    elif status == 605:
        logger.info(f"Invalid file extension for URL: {url}")
    elif status == 606:
        logger.error(f"Exception in parsing URL: {url}")
    elif status == 607:
        content_length = resp.raw_response.headers.get('content-length', 'unknown')
        logger.info(f"Content too big for URL: {url}. Size: {content_length}")
    elif status == 608:
        logger.info(f"Denied by robots.txt rules for URL: {url}")
    
    frontier.mark_url_complete(url)

def extract_next_links(url, resp):
    """
    Extracts all URLs from the HTML content of the response.

    Args:
        url (str): The URL being processed.
        resp (utils.response.Response): The response object with the page content.

    Returns:
        list: A list of URLs found in the page.
    """
    if resp.status != 200 or not resp.raw_response:
        logger.info(f"Request unsuccessful for {url}, returning empty list")
        return []

    # Parse HTML content
    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
    links = []

    # Extract valid hyperlinks
    for anchor in soup.find_all('a', href=True):
        link = urljoin(url, urlparse(anchor['href'])._replace(fragment='').geturl())
        links.append(link)

    return links

def calculate_depth(url):
    """
    Calculate the depth of the URL based on the number of slashes in its path.

    Args:
        url (str): The URL to calculate depth for.

    Returns:
        int: The depth of the URL.
    """
    return urlparse(url).path.count('/')

def is_empty_page(content):
    """
    Check if the page content is empty.

    Args:
        content (bytes): The raw content of the page.

    Returns:
        bool: True if the content is empty, False otherwise.
    """
    return not content.strip()

def detect_potential_trap(url):
    """
    Detects potential traps based on URL patterns, repetitive query parameters, or known traps.

    Args:
        url (str): The URL to check.

    Returns:
        bool: True if the URL is a potential trap, False otherwise.
    """
    # repetitive patterns
    repetitive_patterns = ["/?", "&page=", "&start=", "&filter=", "&sort="]
    if any(pattern in url for pattern in repetitive_patterns):
        return True

    # limit number of query parameters
    query_count = urlparse(url).query.count('&')
    if query_count > 5:  # arbitrary threshold
        return True

    return False

def is_valid(url):
    """
    Validates if a URL should be crawled.

    Args:
        url (str): The URL to check.

    Returns:
        bool: True if the URL is valid for crawling, False otherwise.
    """
    try:
        parsed = urlparse(url)
        
        # ensure URL scheme is HTTP/HTTPS
        if parsed.scheme not in {"http", "https"}:
            return False
        
        # handle robots.txt compliance
        if not can_fetch(url):
            logger.info(f"Blocked by robots.txt: {url}")
            return False
        
        large_file_extensions = (
            ".pdf", ".docx", ".mp4", ".mp3", ".avi", ".mov", ".zip", ".rar"
        )
        
        if any(url.lower().endswith(ext) for ext in large_file_extensions):
            logger.info(f"Skipping large file: {url}")
            return False
        
        # common traps and patterns to exclude
        trap_terms = [
            "/tag/", "/page/", "/category/", "/paged=", "/?tag", "/archive/",
            "partnerships_posts", "institutes_centers", "research_areas_ics",
            "calendar/event?action=template", "/?ical=1", "/day/", "/week/", "/month/",
            "eventdisplay=past", "tribe-bar-date", "post_type=tribe_events",
            "/events/", "/event/", "/wp-login.php", "action=login", "action=edit",
            "/wiki/", "/wiki?", "/wikiword", "/wikisandbox", "/pmwiki", "cookbook",
            "/sitemap", "csdl/trans", "ieeexplore", "/petko", "/pmichaud", "wikivoyage",
            "en.wiktionary", "/indexdot", "home?action=login", "google.com/calendar",
            "linkedin.com/share", "twitter.com/share", "facebook.com/sharer",
            "zoom.us", "docs.google.com", "drive.google.com", "youtu.be", "youtube.com",
            "confirmsubscription", "forms.gle", "subscribe", "google.com/maps", 
            "calendar.google.com", "/~seal/projects/", "/wp-login.php", "redirect_to=", 
            "index.php?p=", "?filter%5B"
        ]
        
        # check if the URL matches any known traps
        if any(term in url.lower() for term in trap_terms):
            logger.info(f"Skipping potential trap URL: {url}")
            return False
        
        # numeric publications
        if re.search(r'/r\d+\.html$', url.lower()):
            logger.info(f"Skipping numeric trap URL: {url}")
            return False
        
        if re.search(r'/ics_x33/\w+\.html$', url.lower()):
            logger.info(f"Skipping repetitive trap URL: {url}")
            return False

        
        # restrict to specified UCI domains
        allowed_domains = [
            "ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu",
            "today.uci.edu/department/information_computer_sciences"
        ]
        if not any(domain in parsed.netloc for domain in allowed_domains):
            return False
        
        # filter out URLs based on file extensions (non-HTML content)
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico|png|tiff?|mid|mp2|mp3|mp4|wav|avi|mov|"
            r"mpeg|ram|m4v|mkv|ogg|ogv|pdf|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|"
            r"data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1|"
            r"thmx|mso|arff|rtf|jar|csv|rm|smil|wmv|swf|wma|zip|rar|gz)$",
            parsed.path.lower()
        ):
            return False
        
        return True

    except Exception as e:
        logger.error(f"Error validating URL: {url}, {e}")
        return False