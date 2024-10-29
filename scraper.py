import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import logging
import urllib.robotparser
from urllib.parse import urlparse
from collections import Counter

MAX_DEPTH = 5
MIN_WORD_COUNT = 50

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

robots_cache = {}
words_counter = Counter()

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

def word_counter(content):

   # create list of English stop words

   stop_w = [
       "a", "about", "above", "after", "again", "against", "all",
       "am", "an", "and", "any", "are", "aren't", "as", "at", "be",
       "because", "been", "before", "being", "below", "between", "both",
       "but", "by", "can't", "cannot", "could", "couldn't", "did", "didn't",
       "do", "does", "doesn't", "doing", "don't", "down", "during", "each",
       "few", "for", "from", "further", "had", "hadn't", "has", "hasn't",
       "have", "haven't", "having", "he", "he'd", "he'll", "he's", "her",
       "here", "here's", "hers", "herself", "him", "himself", "his", "how",
       "how's", "i", "i'd", "i'll", "i'm", "i've", "if", "in", "into", "is",
       "isn't", "it", "it's", "its", "itself", "let's", "me", "more", "most",
       "mustn't", "my", "myself", "no", "nor", "not", "of", "off", "on", "once",
       "only", "or"]
   

def scraper(url, resp, frontier):
    """
    Extracts and filters valid URLs from a page's response.

    Args:
        url (str): The URL being processed.
        resp (utils.response.Response): The response object with the page content.
        frontier (Frontier): The frontier to mark URLs as complete.

    Returns:
        list: A list of valid URLs for further crawling.
    """
    # Check if the page is low-information
    # if is_low_information(resp.raw_response.content):
    #     logger.info(f"Skipping low-information URL: {url}")
    #     frontier.mark_url_complete(url, low_information=True)
    #     return []

    # Extract links from the page content
    links = extract_next_links(url, resp)
    valid_links = []

    for link in links:
        if is_valid(link):
            depth = url.count('/')  # Simple heuristic for depth
            if depth < MAX_DEPTH:
                valid_links.append(link)
            else:
                logger.info(f"Skipping {link} - Exceeded max depth")
        # else:
        #     logger.info(f"Skipping {link} - Invalid URL")  # Log invalid URLs

    # Mark the original URL as complete
    frontier.mark_url_complete(url)
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
        
        # Ensure URL scheme is HTTP/HTTPS
        if parsed.scheme not in {"http", "https"}:
            return False
        
        # Handle robots.txt compliance
        if not can_fetch(url):
            logger.info(f"Blocked by robots.txt: {url}")
            return False
        
        # Common traps and patterns to exclude
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
        
        # Check if the URL matches any known traps
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

        
        # Restrict to specified UCI domains
        allowed_domains = [
            "ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu",
            "today.uci.edu/department/information_computer_sciences"
        ]
        if not any(domain in parsed.netloc for domain in allowed_domains):
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

    except Exception as e:
        logger.error(f"Error validating URL: {url}, {e}")
        return False