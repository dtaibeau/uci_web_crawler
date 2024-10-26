import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import logging

MAX_DEPTH = 5
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def scraper(url, resp):
    """
    Extracts and filters valid URLs from a page's response.

    Args:
        url (str): The URL being processed.
        resp (utils.response.Response): The response object with the page content.

    Returns:
        list: A list of valid URLs for further crawling.
    """
    links = extract_next_links(url, resp)
    valid_links = []
    for link in links:
        if is_valid(link):
            depth = url.count('/')  # simple heuristic for depth
            if depth < MAX_DEPTH:
                valid_links.append(link)
            else:
                logger.info(f"Skipping {link} - Exceeded max depth")
    return valid_links

def extract_next_links(url, resp):
    """
    Extracts all URLs from the HTML content of the response.

    Args:
        url (str): The URL being processed.
        resp (utils.response.Response): The response with the page content.

    Returns:
        list: A list of URLs found in the page.
    """
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    
    # if request unsuccessful, return empty list
    if resp.status != 200 or resp.raw_response is None:
        print('request unsuccessful, returning empty list')
        return []
    
    # otherwise, parse through raw HTML from response obj
    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
    links = []

    # extract all valid hyperlinks (<a> href="...")
    for anchor in soup.find_all('a', href=True):
        link = anchor['href']

        # normalize link (gets rid of #'...' at end of url)
        link = urljoin(url, urlparse(link)._replace(fragment='').geturl())
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
    parsed = urlparse(url)
    return parsed.path.count('/')


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
        if parsed.scheme not in {"http", "https"}:
            return False

        # Check for dynamic patterns and traps
        if 'filter%5B' in url.lower() or 'filter[' in url.lower():
            return False

        # Date-based traps (e.g., /2021/05/25/)
        if re.search(r'/\d{4}/\d{2}/\d{2}/', url):
            logger.info(f"Skipping date-based trap URL: {url}")
            return False

        # Skip URLs with specific patterns (potential traps)
        trap_terms = [
            "/tag/", "/page/", "/category/", "/paged=", "/?tag", "/archive/",
            "partnerships_posts", "institutes_centers", "research_areas_ics",
            "calendar/event?action=template", "/?ical=1", "/day/", "/week/", "/month/",
            "eventdisplay=past", "tribe-bar-date", "post_type=tribe_events", "/events/",
            "action=login", "action=edit", "/wiki/", "/wiki?", "/wikiword",
            "/wikisandbox", "/pmwiki", "cookbook", "/sitemap", "csdl/trans",
            "ieeexplore", "/petko", "/pmichaud", "wikivoyage", "en.wiktionary",
            "/indexdot", "home?action=login", "/event/"
        ]
        if any(term in url.lower() for term in trap_terms):
            logger.info(f"Skipping potential trap URL: {url}")
            return False

        # Restrict crawling to UCI domains only
        if not parsed.netloc.endswith("ics.uci.edu"):
            return False

        # Filter out URLs based on file extensions (non-HTML content)
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico|png|tiff?|mid|mp2|mp3|mp4|wav|avi|mov|"
            r"mpeg|ram|m4v|mkv|ogg|ogv|pdf|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|"
            r"data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1|"
            r"thmx|mso|arff|rtf|jar|csv|rm|smil|wmv|swf|wma|zip|rar|gz)$",
            parsed.path.lower()
        ):
            return False

        return True

    except TypeError:
        logger.error(f"TypeError for URL: {url}")
        return False
